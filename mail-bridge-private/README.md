# Mail Bridge private plugin 0.4.0

此包通过 Streamable HTTP + OAuth/DCR 连接已有服务 https://mail.example.com/mcp。
它不托管服务器，也不保存邮箱密码。默认只请求 mail:read；SMTP 与事件另行授权。

## 在聊天中添加邮箱

用户提出添加邮箱时，调用 `begin_account_setup`，展示返回的私密配置链接。
用户在十分钟内打开网页，填写 IMAP 连接信息、邮箱客户端密码/授权码及独立 owner
密码。凭据直接提交服务端，不进入聊天。网页支持 TLS/STARTTLS，SMTP 信息可选，
新账户发信默认关闭；添加账户不会创建事件订阅。

提交后账户立即进入同一个运行时账户库，无需重启。使用返回的 setup_id 调用
`account_setup_status` 查看 pending/saved，再用 `list_accounts` / `configuration_status`
查看账户。saved/ready 只说明配置保存成功，不能证明邮箱已登录；真实读取仍需用户请求。
服务重启后账户及已有 OAuth 保留。配置链接与临时状态在十分钟后或服务重启后失效，
已保存账户仍可用 list_accounts 查看。

## 连接与部署

在真正的 OAuth 页面私密输入独立 owner 密码。不要在聊天或插件字段填写邮箱密码。
服务端部署及旧账户迁移由服务端项目维护，参见该项目的 `deploy/SETUP.md`。
插件包不包含服务器部署或凭据填写脚本。

portable mcp.json 保持原有 type/url，不包含服务器级 extensions。客户端通过
未授权 MCP 的 WWW-Authenticate 和 discovery 元数据发现 OAuth/DCR。
安装成功不代表 OAuth 或邮箱连接成功。首次连接检查只列账户与配置状态，不读邮件，
不发测试信。更新已有插件，保留其身份与访问范围，避免重复创建。
