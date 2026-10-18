# Mail Bridge private plugin 0.3.1

此包连接已有服务 https://mail.example.com/mcp，采用 Streamable HTTP + OAuth/DCR。
它不托管服务器、不包含邮箱密码，也不代表已完成平台 OAuth 或真实邮箱联通。
服务是否运行以实时检查为准；SMTP 和事件保持关闭。已有配置无需重新输入密码。

## 配置与连接

服务器配置由服务端项目维护，详见仓库中的
[服务器配置说明](../mail-bridge-rust/deploy/SETUP.md)。独立安装的插件包不包含
部署脚本；需要配置服务器时，请从 Mail Bridge 服务端源码获取该说明和脚本。
已有配置无需重复输入密码。

服务就绪后安装或连接此插件，在真正的 OAuth 页面私密输入独立 owner 密码。
默认只请求 mail:read。先调用 list_accounts / configuration_status 检查账户配置；
这两项不会登录邮箱，也不能证明真实邮箱已连通。

0.3.1 的 portable mcp.json 只声明 type 和 url，不含服务器级 extensions。
公开 Agent Plugins 1.0.0 schema 及 Codex portable 解析器不接受该扩展字段；
移除它是加载兼容性修正，不是关闭服务端 OAuth。客户端应根据未授权 MCP 的
WWW-Authenticate 和 /.well-known 元数据发现 OAuth/DCR。
服务端挑战请求 mail:read，授权请求未提供 scope 时服务端默认 mail:read。
若客户端显示 mail:send 或 mail:events，先不要授予额外权限，记录非敏感错误信息。

必须分别验证：包校验通过、宿主加载 MCP、出现授权入口、OAuth 成功、工具可用。
安装成功不代表连接成功。已有私有插件应原位更新；不要重复创建或另建 MCP 插件。
首次验证只列配置账户和配置状态，不读取邮件、不发测试信。

提供的代码/测试不能替代实际 QQ/ZJU 登录、OAuth 平台连接和事件端到端验证。
