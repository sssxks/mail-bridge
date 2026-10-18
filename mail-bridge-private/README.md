# Mail Bridge private plugin 0.3

此包连接已有服务 https://mail.example.com/mcp，采用 Streamable HTTP + OAuth/DCR。
它不托管服务器、不包含邮箱密码，也不代表已完成平台 OAuth 或真实邮箱联通。
服务器升级后仍停止且未设开机启动；SMTP 和事件保持关闭。

## 用户最后需要手动完成的步骤

1. 在自己的私密终端进入服务器；在现有 pc3 WSL 环境可使用 `ssh example-host`。
2. 手动执行 `sudo bash /opt/mail-bridge-rust/setup-mail-bridge.sh`。
   脚本提示 QQ 完整地址（含 @qq.com）及浙大完整地址（含 @zju.edu.cn）。
   你输入的客户端密码/授权码均隐藏输入并要求重复；存在的密码文件不会被读取或覆盖。
   QQ 使用邮箱客户端授权码；浙大启用二次认证时使用客户端专用密码。
   分别写入 `/etc/mail-bridge-rust/mailboxes/qq` 和 `mailboxes/zju`，互不共用。
   再输入自己准备的、与邮箱密码不同的 32–256 字符 ASCII owner 密码，
   保存到 `/etc/mail-bridge-rust/owner_password`。这是 OAuth 授权页密码。
   文件 root 所有，0600；目录 0700。脚本不会打印密码或把密码交给外部进程参数。
   不要把秘密写进命令、聊天、配置 JSON、日志或插件包。脚本不会启动服务。
3. 配置完成后自行执行 `sudo systemctl start mail-bridge-rust.service`。
   启动 HTTP 服务本身不会打开邮箱，因为事件关闭且没有邮件请求。
   暂不执行 enable，避免在决定前新增开机持续运行。
4. 在自己的浏览器检查 `https://mail.example.com/.well-known/oauth-protected-resource`。
   正常应返回 OAuth 资源元数据；未授权 `/mcp` 返回401是预期。
   服务停止时502是预期，不能声称此时已连通。
5. 由父会话用这个包创建一个私有插件（已有同名插件应先检查并更新，避免重复）。
   安装/连接后仅在真正的 OAuth 页面私密输入 owner 密码。默认只请求 mail:read。
   先调用 list_accounts / configuration_status；这两项不会登录邮箱。
   真实列邮件/读邮件仍是后续明确的用户请求。不要用发测试信验证连接。

服务单元使用 systemd252 的目录凭据映射：
LoadCredential=mailboxes:/etc/mail-bridge-rust/mailboxes，导入后文件名为
mailboxes_qq / mailboxes_zju，程序自动识别；config.json 中 password_file 为 qq/zju。
用户若已有自定义映射，脚本按 config.json 中映射写入，不猜测密码内容。

服务中 `/etc/mail-bridge-rust/service.env` 保留原状。
新增 `/etc/mail-bridge-rust/safety.env` 强制 MAIL_BRIDGE_EVENTS_ENABLED=false。
所有账户 smtp_enabled=false。发信与事件启用属于后续单独动作。
没有实际发信、邮箱登录、事件订阅、回调或平台签名密钥被创建。

包内 MCP auth 使用 Plugin Creator 当前 OpenAI 扩展格式：
extensions.com.openai.auth.type=oauth, client.mode=dcr,
baseScopes/defaultScopes=[mail:read]。端点由已有 HTTPS 路由及服务源码确定；
OAuth 发现依照服务器 /.well-known 元数据。此时实时发现仍受 owner 手动设置所阻。
公开 Agent Plugins 基础 mcp schema 比 OpenAI 扩展配置更窄；不要把剥除扩展后的
基础结构校验误报成平台实测。实际安装/发现结果必须由平台返回后确认。

提供的代码/测试不能替代实际 QQ/ZJU 登录、OAuth 平台连接和事件端到端验证。
