// ES Module格式的Cloudflare Worker

export default {
	async fetch(request, env, ctx) {
		return await handleRequest(request, env);
	}
};

async function handleRequest(request, env) {
	const url = new URL(request.url);
	const clientIP = request.headers.get('CF-Connecting-IP');

	// 检查请求路径
	if (url.pathname === '/') {
		return new Response('IP查询服务', {
			headers: { 'Content-Type': 'text/plain' }
		});
	} else if (url.pathname === '/admin') {
		// 管理界面路径
		return handleAdminInterface(request, env);
	} else if (url.pathname.startsWith('/api/query/')) {
		// API查询路径
		return handleAPIQuery(request, clientIP, env);
	} else if (url.pathname === '/api/list') {
		// 新增: IP列表导出路径
		return handleIPList(request, clientIP, env);
	} else {
		return new Response('Not Found', { status: 404 });
	}
}

async function handleAPIQuery(request, clientIP, env) {
	// 检查IP是否在黑名单中
	const blacklistData = await env.BLACKLIST.get(clientIP);
	if (blacklistData) {
		const blacklistInfo = JSON.parse(blacklistData);
		if (blacklistInfo.expiresAt > Date.now()) {
			return new Response('Access Denied: Your IP has been temporarily blocked', {
				status: 403
			});
		} else {
			// 黑名单已过期，删除记录
			await env.BLACKLIST.delete(clientIP);
		}
	}

	// 提取主机名
	const url = new URL(request.url);
	const hostname = url.pathname.replace('/api/query/', '');

	if (!hostname) {
		return new Response('Hostname is required', { status: 400 });
	}

	// 处理Basic认证
	const authHeader = request.headers.get('Authorization');
	if (!authHeader || !authHeader.startsWith('Basic ')) {
		return new Response('Authentication required', {
			status: 401,
			headers: {
				'WWW-Authenticate': 'Basic realm="IP Query Service"'
			}
		});
	}

	// 获取配置
	const configData = await env.CONFIG.get('service_config');
	const config = configData ? JSON.parse(configData) : {
		maxFailedAttempts: 5,
		blacklistDuration: 7 * 24 * 60 * 60 * 1000, // 7天，以毫秒为单位
		credentials: {
			username: 'admin',
			password: 'password'
		}
	};

	// 验证凭据
	const base64Credentials = authHeader.split(' ')[1];
	const credentials = atob(base64Credentials);
	const [username, password] = credentials.split(':');

	if (username !== config.credentials.username || password !== config.credentials.password) {
		// 认证失败，记录失败尝试
		await recordFailedAttempt(clientIP, config, env);
		return new Response('Authentication failed', { status: 401 });
	}

	// 认证成功，重置失败计数
	await env.FAILED_ATTEMPTS.delete(clientIP);

	// 获取主机名对应的IP
	const hostDataString = await env.HOST_IP_MAPPINGS.get(hostname);
	if (!hostDataString) {
		return new Response('Hostname not found', { status: 404 });
	}

	// 解析数据
	const hostData = JSON.parse(hostDataString);

	// 返回IP地址
	return new Response(hostData.ip, {
		headers: {
			'Content-Type': 'text/plain',
			'Cache-Control': 'no-store'
		}
	});
}

async function handleIPList(request, clientIP, env) {
    // 检查IP是否在黑名单中
    const blacklistData = await env.BLACKLIST.get(clientIP);
    if (blacklistData) {
        const blacklistInfo = JSON.parse(blacklistData);
        if (blacklistInfo.expiresAt > Date.now()) {
            return new Response('Access Denied: Your IP has been temporarily blocked', {
                status: 403
            });
        } else {
            // 黑名单已过期，删除记录
            await env.BLACKLIST.delete(clientIP);
        }
    }

    // 处理Basic认证
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Basic ')) {
        return new Response('Authentication required', {
            status: 401,
            headers: {
                'WWW-Authenticate': 'Basic realm="IP Query Service"'
            }
        });
    }

    // 获取配置
    const configData = await env.CONFIG.get('service_config');
    const config = configData ? JSON.parse(configData) : {
        maxFailedAttempts: 5,
        blacklistDuration: 7 * 24 * 60 * 60 * 1000, // 7天，以毫秒为单位
        credentials: {
            username: 'admin',
            password: 'password'
        }
    };

    // 验证凭据
    const base64Credentials = authHeader.split(' ')[1];
    const credentials = atob(base64Credentials);
    const [username, password] = credentials.split(':');

    if (username !== config.credentials.username || password !== config.credentials.password) {
        // 认证失败，记录失败尝试
        await recordFailedAttempt(clientIP, config, env);
        return new Response('Authentication failed', { status: 401 });
    }

    // 认证成功，重置失败计数
    await env.FAILED_ATTEMPTS.delete(clientIP);

    // 获取所有主机名和IP映射
    const hostIpPairs = [];
    let hostListComplete = false;
    let cursor = null;
    
    while (!hostListComplete) {
        const listResult = await env.HOST_IP_MAPPINGS.list({ cursor });
        for (const key of listResult.keys) {
            const hostDataString = await env.HOST_IP_MAPPINGS.get(key.name);
            let hostData;
            try {
                hostData = JSON.parse(hostDataString);
                hostIpPairs.push({ 
                    hostname: key.name, 
                    ip: hostData.ip
                });
            } catch (e) {
                // 如果解析失败，说明是旧格式，仅包含IP
                hostIpPairs.push({ 
                    hostname: key.name, 
                    ip: hostDataString
                });
            }
        }
        
        cursor = listResult.cursor;
        hostListComplete = listResult.list_complete;
    }

    // 提取所有IP地址并去重
    const uniqueIPs = [...new Set(hostIpPairs.map(pair => pair.ip))];
    
    // 生成IP列表，每行一个IP
    const ipList = uniqueIPs.join('\n');
    
    // 返回IP列表
    return new Response(ipList, {
        headers: {
            'Content-Type': 'text/plain',
            'Content-Disposition': 'attachment; filename="whitelist"',
            'Cache-Control': 'no-store'
        }
    });
}

async function recordFailedAttempt(clientIP, config, env) {
	// 获取当前失败尝试计数
	const failedAttemptsData = await env.FAILED_ATTEMPTS.get(clientIP);
	const today = new Date().toISOString().split('T')[0]; // 获取今天的日期，格式为YYYY-MM-DD
	let failedAttempts = failedAttemptsData ? JSON.parse(failedAttemptsData) : { date: today, count: 0 };

	// 如果是新的一天，重置计数
	if (failedAttempts.date !== today) {
		failedAttempts = { date: today, count: 1 };
	} else {
		failedAttempts.count += 1;
	}

	// 更新失败尝试记录
	await env.FAILED_ATTEMPTS.put(clientIP, JSON.stringify(failedAttempts));

	// 检查是否达到最大失败尝试次数
	if (failedAttempts.count >= config.maxFailedAttempts) {
		// 将IP加入黑名单
		const blacklistInfo = {
			addedAt: Date.now(),
			expiresAt: Date.now() + config.blacklistDuration,
			reason: `Exceeded maximum failed authentication attempts (${config.maxFailedAttempts}) on ${today}`
		};

		await env.BLACKLIST.put(clientIP, JSON.stringify(blacklistInfo));
		console.log(`IP ${clientIP} has been blacklisted until ${new Date(blacklistInfo.expiresAt).toISOString()}`);
	}
}

// 新增：记录管理页面认证失败的函数
async function recordAdminFailedAttempt(clientIP, config, env) {
	// 获取当前失败尝试计数
	const failedAttemptsData = await env.FAILED_ATTEMPTS.get(clientIP);
	const today = new Date().toISOString().split('T')[0]; // 获取今天的日期，格式为YYYY-MM-DD
	let failedAttempts = failedAttemptsData ? JSON.parse(failedAttemptsData) : { date: today, count: 0 };
	
	// 如果是新的一天，重置计数
	if (failedAttempts.date !== today) {
	  failedAttempts = { date: today, count: 1 };
	} else {
	  failedAttempts.count += 1;
	}
	
	// 更新失败尝试记录
	await env.FAILED_ATTEMPTS.put(clientIP, JSON.stringify(failedAttempts));
	
	// 检查是否达到最大失败尝试次数
	if (failedAttempts.count >= config.maxFailedAttempts) {
	  // 将IP加入黑名单
	  const blacklistInfo = {
		addedAt: Date.now(),
		expiresAt: Date.now() + config.blacklistDuration,
		reason: `Exceeded maximum failed admin authentication attempts (${config.maxFailedAttempts}) on ${today}`
	  };
	  
	  await env.BLACKLIST.put(clientIP, JSON.stringify(blacklistInfo));
	  console.log(`IP ${clientIP} has been blacklisted for admin access until ${new Date(blacklistInfo.expiresAt).toISOString()}`);
	}
  }

async function handleAdminInterface(request, env) {
	const url = new URL(request.url);
  const clientIP = request.headers.get('CF-Connecting-IP');
  
  // 首先检查IP是否在黑名单中
  const blacklistData = await env.BLACKLIST.get(clientIP);
  if (blacklistData) {
    const blacklistInfo = JSON.parse(blacklistData);
    if (blacklistInfo.expiresAt > Date.now()) {
      return new Response('Access Denied: Your IP has been temporarily blocked due to excessive failed login attempts.', {
        status: 403,
        headers: { 'Content-Type': 'text/html' }
      });
    } else {
      // 黑名单已过期，删除记录
      await env.BLACKLIST.delete(clientIP);
    }
  }
  
  // 验证管理员身份
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return new Response('Admin authentication required', {
      status: 401,
      headers: {
        'WWW-Authenticate': 'Basic realm="IP Query Service Admin"'
      }
    });
  }
  
  // 获取配置以检查管理员凭据
  const configData = await env.CONFIG.get('service_config');
  const config = configData ? JSON.parse(configData) : {
    maxFailedAttempts: 5,
    blacklistDuration: 7 * 24 * 60 * 60 * 1000,
    credentials: {
      username: 'admin',
      password: 'password'
    },
    adminCredentials: {
      username: 'admin',
      password: 'admin'
    }
  };
  
  // 验证管理员凭据
  const base64Credentials = authHeader.split(' ')[1];
  const credentials = atob(base64Credentials);
  const [username, password] = credentials.split(':');
  
  if (username !== config.adminCredentials.username || password !== config.adminCredentials.password) {
    // 认证失败，记录失败尝试
    await recordAdminFailedAttempt(clientIP, config, env);
    return new Response('Admin authentication failed', { status: 401 });
  }
  
  // 认证成功，重置失败计数
  await env.FAILED_ATTEMPTS.delete(clientIP);
  
  // 确定当前活动的标签
  const activeTab = url.searchParams.get('tab') || 'system';
  
  // 处理POST请求以更新配置
  if (request.method === 'POST') {
    try {
      const formData = await request.formData();
      
      // 根据表单action字段确定操作类型
      const action = formData.get('action');
      
      if (action === 'updateConfig') {
        const newConfig = {
          maxFailedAttempts: parseInt(formData.get('maxFailedAttempts'), 10) || config.maxFailedAttempts,
          blacklistDuration: parseInt(formData.get('blacklistDuration'), 10) * 24 * 60 * 60 * 1000 || config.blacklistDuration,
          credentials: {
            username: formData.get('apiUsername') || config.credentials.username,
            password: formData.get('apiPassword') || config.credentials.password
          },
          adminCredentials: {
            username: formData.get('adminUsername') || config.adminCredentials.username,
            password: formData.get('adminPassword') || config.adminCredentials.password
          }
        };
        
        // 保存新配置
        await env.CONFIG.put('service_config', JSON.stringify(newConfig));
      } 
      else if (action === 'updateHostMapping') {
        // 处理主机名和IP映射的更新
        const hostname = formData.get('hostname');
        const ipAddress = formData.get('ipAddress');
        const remarks = formData.get('remarks') || '';
        
        if (hostname && ipAddress) {
          // 将IP和备注信息存储为JSON
          const hostData = {
            ip: ipAddress,
            remarks: remarks
          };
          await env.HOST_IP_MAPPINGS.put(hostname, JSON.stringify(hostData));
        }
      }
      else if (action === 'editHostMapping') {
        // 处理编辑主机名映射
        const hostname = formData.get('hostname');
        const ipAddress = formData.get('ipAddress');
        const remarks = formData.get('remarks') || '';
        
        if (hostname && ipAddress) {
          const hostData = {
            ip: ipAddress,
            remarks: remarks
          };
          await env.HOST_IP_MAPPINGS.put(hostname, JSON.stringify(hostData));
        }
      }
      else if (action === 'deleteHost') {
        // 处理删除主机名操作
        const hostnameToDelete = formData.get('hostname');
        if (hostnameToDelete) {
          await env.HOST_IP_MAPPINGS.delete(hostnameToDelete);
        }
      }
      else if (action === 'manageBlacklist') {
        // 处理黑名单操作
        const blacklistOperation = formData.get('blacklistOperation');
        const ipToManage = formData.get('ipAddress');
        
        if (blacklistOperation === 'add' && ipToManage) {
          const blacklistInfo = {
            addedAt: Date.now(),
            expiresAt: Date.now() + config.blacklistDuration,
            reason: 'Manually added by admin'
          };
          await env.BLACKLIST.put(ipToManage, JSON.stringify(blacklistInfo));
        } 
        else if (blacklistOperation === 'remove' && ipToManage) {
          await env.BLACKLIST.delete(ipToManage);
        }
      }
      
      // 确定重定向回哪个标签页
      let redirectTab = 'system';
      if (action === 'updateHostMapping' || action === 'deleteHost' || action === 'editHostMapping') {
        redirectTab = 'hostmap';
      } else if (action === 'manageBlacklist') {
        redirectTab = 'blacklist';
      }
      
      return new Response('Settings updated successfully', {
        status: 302,
        headers: { 'Location': `/admin?tab=${redirectTab}` }
      });
    } catch (error) {
      return new Response(`Error updating settings: ${error.message}`, { status: 500 });
    }
  }
  
  // 获取所有主机名IP映射
  const hostIpPairs = [];
  let hostListComplete = false;
  let cursor = null;
  
  while (!hostListComplete) {
    const listResult = await env.HOST_IP_MAPPINGS.list({ cursor });
    for (const key of listResult.keys) {
      const hostDataString = await env.HOST_IP_MAPPINGS.get(key.name);
      let hostData;
      try {
        // 尝试解析为JSON格式
        hostData = JSON.parse(hostDataString);
      } catch (e) {
        // 如果解析失败，说明是旧格式，仅包含IP
        hostData = { ip: hostDataString, remarks: '' };
        // 更新为新格式
        await env.HOST_IP_MAPPINGS.put(key.name, JSON.stringify(hostData));
      }
      hostIpPairs.push({ 
        hostname: key.name, 
        ip: hostData.ip,
        remarks: hostData.remarks || ''
      });
    }
    
    cursor = listResult.cursor;
    hostListComplete = listResult.list_complete;
  }
  
  // 获取黑名单
  const blacklist = [];
  let blacklistComplete = false;
  cursor = null;
  
  while (!blacklistComplete) {
    const listResult = await env.BLACKLIST.list({ cursor });
    for (const key of listResult.keys) {
      const blacklistData = await env.BLACKLIST.get(key.name);
      const blacklistInfo = JSON.parse(blacklistData);
      blacklist.push({
        ip: key.name,
        expiresAt: new Date(blacklistInfo.expiresAt).toLocaleString(),
        reason: blacklistInfo.reason
      });
    }
    
    cursor = listResult.cursor;
    blacklistComplete = listResult.list_complete;
  }

	// 渲染管理界面
	const html = `
	<!DOCTYPE html>
	<html>
	<head>
	  <title>IP查询服务管理界面</title>
	  <meta charset="UTF-8">
	  <meta name="viewport" content="width=device-width, initial-scale=1.0">
	  <style>
		body { 
		  font-family: Arial, sans-serif; 
		  line-height: 1.6; 
		  margin: 0; 
		  padding: 0;
		  color: #333;
		  background-color: #f5f5f5;
		}
		
		.container { 
		  max-width: 1200px; 
		  margin: 0 auto; 
		  padding: 20px;
		}
		
		header {
		  background-color: #2c3e50;
		  color: white;
		  padding: 1rem;
		  text-align: center;
		  margin-bottom: 20px;
		}
		
		h1 { margin: 0; }
		
		/* 标签页样式 */
		.tabs {
		  display: flex;
		  margin-bottom: 20px;
		  border-bottom: 1px solid #ddd;
		  background-color: #fff;
		  border-radius: 4px 4px 0 0;
		}
		
		.tab-link {
		  padding: 15px 20px;
		  cursor: pointer;
		  transition: background-color 0.3s;
		  font-weight: bold;
		  color: #555;
		  text-decoration: none;
		}
		
		.tab-link:hover {
		  background-color: #f1f1f1;
		}
		
		.tab-link.active {
		  background-color: #3498db;
		  color: white;
		}
		
		/* 标签内容样式 */
		.tab-content {
		  display: none;
		  background-color: #fff;
		  padding: 20px;
		  border-radius: 0 0 4px 4px;
		  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
		}
		
		.tab-content.active {
		  display: block;
		}
		
		/* 表单样式 */
		.form-group { 
		  margin-bottom: 15px; 
		}
		
		label { 
		  display: block; 
		  margin-bottom: 5px; 
		  font-weight: bold; 
		  color: #555;
		}
		
		input[type="text"], 
		input[type="password"], 
		input[type="number"],
		textarea { 
		  width: 100%; 
		  padding: 10px; 
		  border: 1px solid #ddd;
		  border-radius: 4px;
		  box-sizing: border-box;
		}
		
		textarea {
		  resize: vertical;
		  min-height: 60px;
		}
		
		button { 
		  background: #3498db; 
		  color: white; 
		  padding: 10px 15px; 
		  border: none; 
		  cursor: pointer; 
		  border-radius: 4px;
		  font-weight: bold;
		}
		
		button:hover { 
		  background: #2980b9; 
		}
		
		button.btn-danger {
		  background: #e74c3c;
		}
		
		button.btn-danger:hover {
		  background: #c0392b;
		}
		
		button.btn-edit {
		  background: #f39c12;
		}
		
		button.btn-edit:hover {
		  background: #d35400;
		}
		
		button.btn-success {
		  background: #2ecc71;
		}
		
		button.btn-success:hover {
		  background: #27ae60;
		}
		
		/* 表格样式 */
		table { 
		  width: 100%; 
		  border-collapse: collapse; 
		  margin-bottom: 20px; 
		  box-shadow: 0 1px 3px rgba(0,0,0,0.1);
		}
		
		th, td { 
		  padding: 12px 15px; 
		  text-align: left; 
		  border-bottom: 1px solid #ddd; 
		}
		
		th { 
		  background-color: #f2f2f2; 
		  font-weight: bold;
		  color: #555;
		}
		
		tr:hover {
		  background-color: #f5f5f5;
		}
		
		.card {
		  background: white;
		  border-radius: 4px;
		  padding: 20px;
		  margin-bottom: 20px;
		  box-shadow: 0 1px 3px rgba(0,0,0,0.1);
		}
		
		.card h2 {
		  margin-top: 0;
		  border-bottom: 1px solid #eee;
		  padding-bottom: 10px;
		  color: #2c3e50;
		}
		
		footer {
		  text-align: center;
		  margin-top: 40px;
		  padding: 10px;
		  color: #777;
		  font-size: 14px;
		}
		
		/* 编辑模式 */
		.edit-mode {
		  display: none;
		}
		
		.view-mode {
		  display: block;
		}
		
		tr.editing .view-mode {
		  display: none;
		}
		
		tr.editing .edit-mode {
		  display: block;
		}
		
		.action-buttons {
		  white-space: nowrap;
		}
	  </style>
	</head>
	<body>
	  <header>
		<h1>IP查询服务管理界面</h1>
	  </header>
	  
	  <div class="container">
		<!-- 标签导航 -->
		<div class="tabs">
		  <a href="/admin?tab=system" class="tab-link ${activeTab === 'system' ? 'active' : ''}">系统配置</a>
		  <a href="/admin?tab=hostmap" class="tab-link ${activeTab === 'hostmap' ? 'active' : ''}">主机名映射</a>
		  <a href="/admin?tab=blacklist" class="tab-link ${activeTab === 'blacklist' ? 'active' : ''}">IP黑名单</a>
		  <a href="/admin?tab=logs" class="tab-link ${activeTab === 'logs' ? 'active' : ''}">系统日志</a>
		</div>
		
		<!-- 系统配置 -->
		<div class="tab-content ${activeTab === 'system' ? 'active' : ''}">
		  <div class="card">
			<h2>系统设置</h2>
			<form method="POST">
			  <input type="hidden" name="action" value="updateConfig">
			  <div class="form-group">
				<label for="maxFailedAttempts">每日最大认证失败次数：</label>
				<input type="number" id="maxFailedAttempts" name="maxFailedAttempts" value="${config.maxFailedAttempts}">
			  </div>
			  
			  <div class="form-group">
				<label for="blacklistDuration">黑名单持续天数：</label>
				<input type="number" id="blacklistDuration" name="blacklistDuration" value="${config.blacklistDuration / (24 * 60 * 60 * 1000)}">
			  </div>
			  
			  <h3>API访问凭据</h3>
			  <div class="form-group">
				<label for="apiUsername">用户名：</label>
				<input type="text" id="apiUsername" name="apiUsername" value="${config.credentials.username}">
			  </div>
			  
			  <div class="form-group">
				<label for="apiPassword">密码：</label>
				<input type="password" id="apiPassword" name="apiPassword" value="${config.credentials.password}">
			  </div>
			  
			  <h3>管理员凭据</h3>
			  <div class="form-group">
				<label for="adminUsername">管理员用户名：</label>
				<input type="text" id="adminUsername" name="adminUsername" value="${config.adminCredentials.username}">
			  </div>
			  
			  <div class="form-group">
				<label for="adminPassword">管理员密码：</label>
				<input type="password" id="adminPassword" name="adminPassword" value="${config.adminCredentials.password}">
			  </div>
			  
			  <button type="submit">保存配置</button>
			</form>
		  </div>
		  
		  <div class="card">
			<h2>API使用指南</h2>
			<p>基本URL格式：<code>/api/query/{hostname}</code></p>
			<p>此API需要Basic Auth认证，使用上面配置的API访问凭据。</p>
			<p>示例请求：</p>
			<pre>curl -u username:password https://your-domain.com/api/query/example.com</pre>
			<p>示例实际应用 - 利用私有解析进行SSH：</p>
			<pre>ssh -p 22 root@$(curl -u username:password https://your-domain.com/api/query/example.com)</pre>
			<p></p>
			<p><strong>请注意：当前Admin页面的认证与API的认证不是同一个账户名密码，但是共享同一个防暴力破解黑名单！</strong></p>
		  </div>

		  <div class="card">
		  	<h2>Bash预设方式快速调用SSH</h2>
			<pre>
# 环境变量配置（可覆盖默认值）
export API_USER="your_username"    # API 用户名
export API_PASS="your_password"    # API 密码
export DEFAULT_SSH_PORT="22"       # 默认 SSH 端口

# 动态 SSH 连接函数
ssh_dynamic() {
    local target_domain="$1"
    local ssh_port="\${2:-$DEFAULT_SSH_PORT}"  # 如果未指定端口，则用默认值

    if [ -z "$target_domain" ]; then
        echo "Usage: ssh_dynamic <domain> [port]" >&2
        return 1
    fi

    ssh -p "$ssh_port" "root@$(curl -s -u "$API_USER:$API_PASS" "https://your-domain.com/api/query/$target_domain")"
}
			</pre>
		  </div>

		  <div class="card">
		  	<h2>获取系统内的IP白名单</h2>
			<pre>curl -u admin:password -o whitelist https://your-domain.com/api/list</pre>
		  </div>
		</div>
		
		<!-- 主机名映射 -->
		<div class="tab-content ${activeTab === 'hostmap' ? 'active' : ''}">
		  <div class="card">
			<h2>添加/更新主机名映射</h2>
			<form method="POST">
			  <input type="hidden" name="action" value="updateHostMapping">
			  <div class="form-group">
				<label for="hostname">主机名：</label>
				<input type="text" id="hostname" name="hostname" placeholder="example.com">
			  </div>
			  
			  <div class="form-group">
				<label for="ipAddress">IP地址：</label>
				<input type="text" id="ipAddress" name="ipAddress" placeholder="192.168.1.1">
			  </div>
			  
			  <div class="form-group">
				<label for="remarks">备注：</label>
				<textarea id="remarks" name="remarks" placeholder="可选：添加关于这个映射的任何备注"></textarea>
			  </div>
			  
			  <button type="submit">添加/更新映射</button>
			</form>
		  </div>
		  
		  <div class="card">
			<h2>现有主机名和IP映射</h2>
			<table id="hostMappingTable">
			  <thead>
				<tr>
				  <th>主机名</th>
				  <th>IP地址</th>
				  <th>备注</th>
				  <th>操作</th>
				</tr>
			  </thead>
			  <tbody>
				${hostIpPairs.map(pair => `
				  <tr id="host-row-${pair.hostname.replace(/\./g, '-')}">
					<td>
					  <div class="view-mode">${pair.hostname}</div>
					  <input type="hidden" class="edit-mode hostname-value" value="${pair.hostname}">
					</td>
					<td>
					  <div class="view-mode">${pair.ip}</div>
					  <div class="edit-mode">
						<input type="text" class="ip-value" value="${pair.ip}">
					  </div>
					</td>
					<td>
					  <div class="view-mode">${pair.remarks}</div>
					  <div class="edit-mode">
						<textarea class="remarks-value">${pair.remarks}</textarea>
					  </div>
					</td>
					<td class="action-buttons">
					  <div class="view-mode">
						<button type="button" class="btn-edit" onclick="editHost('${pair.hostname.replace(/\./g, '-')}')">编辑</button>
						<form method="POST" style="display: inline;">
						  <input type="hidden" name="action" value="deleteHost">
						  <input type="hidden" name="hostname" value="${pair.hostname}">
						  <button type="submit" class="btn-danger">删除</button>
						</form>
					  </div>
					  <div class="edit-mode">
						<form method="POST">
						  <input type="hidden" name="action" value="editHostMapping">
						  <input type="hidden" name="hostname" value="${pair.hostname}">
						  <input type="hidden" class="ip-input" name="ipAddress">
						  <input type="hidden" class="remarks-input" name="remarks">
						  <button type="submit" class="btn-success save-btn">保存</button>
						  <button type="button" class="btn-danger" onclick="cancelEdit('${pair.hostname.replace(/\./g, '-')}')">取消</button>
						</form>
					  </div>
					</td>
				  </tr>
				`).join('')}
			  </tbody>
			</table>
		  </div>
		</div>
		
		<!-- IP黑名单 -->
		<div class="tab-content ${activeTab === 'blacklist' ? 'active' : ''}">
		  <div class="card">
			<h2>IP黑名单管理</h2>
			<form method="POST">
			  <input type="hidden" name="action" value="manageBlacklist">
			  <div class="form-group">
				<label for="ipToManage">IP地址：</label>
				<input type="text" id="ipToManage" name="ipAddress" placeholder="192.168.1.1">
			  </div>
			  
			  <button type="submit" name="blacklistOperation" value="add">添加到黑名单</button>
			  <button type="submit" name="blacklistOperation" value="remove" class="btn-danger">从黑名单移除</button>
			</form>
		  </div>
		  
		  <div class="card">
			<h2>当前黑名单</h2>
			<table>
			  <thead>
				<tr>
				  <th>IP地址</th>
				  <th>过期时间</th>
				  <th>原因</th>
				</tr>
			  </thead>
			  <tbody>
				${blacklist.map(item => `
				  <tr>
					<td>${item.ip}</td>
					<td>${item.expiresAt}</td>
					<td>${item.reason}</td>
				  </tr>
				`).join('')}
			  </tbody>
			</table>
		  </div>
		</div>
		
		<!-- 系统日志 -->
		<div class="tab-content ${activeTab === 'logs' ? 'active' : ''}">
		  <div class="card">
			<h2>系统日志</h2>
			<p>此功能尚未实现。未来将在此显示系统操作和认证日志。</p>
		  </div>
		</div>
		
		<footer>
		  <p>© ${new Date().getFullYear()} IP查询服务管理系统 | 版本 1.0</p>
		</footer>
	  </div>
	  
	  <script>
		// 编辑主机名映射
		function editHost(hostId) {
		  const row = document.getElementById('host-row-' + hostId);
		  row.classList.add('editing');
		}
		
		// 取消编辑
		function cancelEdit(hostId) {
		  const row = document.getElementById('host-row-' + hostId);
		  row.classList.remove('editing');
		}
		
		// 为所有保存按钮添加事件监听器
		document.addEventListener('DOMContentLoaded', function() {
		  const saveBtns = document.querySelectorAll('.save-btn');
		  saveBtns.forEach(btn => {
			btn.addEventListener('click', function(e) {
			  const form = this.closest('form');
			  const row = this.closest('tr');
			  
			  // 获取编辑的值
			  const ipValue = row.querySelector('.ip-value').value;
			  const remarksValue = row.querySelector('.remarks-value').value;
			  
			  // 更新隐藏输入字段
			  form.querySelector('.ip-input').value = ipValue;
			  form.querySelector('.remarks-input').value = remarksValue;
			});
		  });
		});
	  </script>
	</body>
	</html>
	`;

	return new Response(html, {
		headers: { 'Content-Type': 'text/html' }
	});
}