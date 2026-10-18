# 服务部署与账户迁移

## 新安装

1. 将 Linux 二进制安装到 `/opt/mail-bridge-rust/mail-bridge-rust`。
2. owner 在私密终端自行准备 `/etc/mail-bridge-rust/owner_password`：32–256 个
   ASCII 字符，与邮箱密码不同；目录 0700、文件 0600。不要把密码放进命令或聊天。
3. 按 `service.env.example` 设置公开 HTTPS origin 和实际 OAuth callback。
   安装本目录的 systemd 单元。它只导入 owner 密码，账户统一保存在私有 StateDirectory
   的 `mail-bridge.sqlite3` 中，首次启动允许零账户。
4. 为 `/mcp`、`/accounts/setup`、OAuth 与 discovery 路径配置反向代理。
   关闭这些路径的访问日志及请求体/查询串跟踪，保留 Origin/Cookie，禁用缓存、
   落盘请求缓冲和自动上游重试。配置页只向同源 POST，不需要 JS 或外部资源。
5. 启动服务，在插件中完成 OAuth。聊天请求添加邮箱，由私密网页填写连接信息和凭据。
   提交后立即可用，无需重启；保存不代表登录验证，新账户发信保持关闭。

QQ 使用邮箱客户端授权码；浙大启用二次认证时使用客户端专用密码。
网页当前支持 TLS / STARTTLS + 密码认证，不包含邮箱服务商专用 OAuth。

## 从 0.3 一次性迁移

`migrate-accounts.py` 是离线迁移工具，不是运行时配置回退路径。服务必须停止。
先在服务器创建 root 私有备份，保留原二进制、systemd/nginx 配置、旧账户文件及
完整数据库。不要导出这些私密文件到聊天或插件包。

```bash
sudo systemctl stop mail-bridge-rust.service
sudo python3 deploy/migrate-accounts.py \
  --config LEGACY_ACCOUNT_JSON \
  --password-dir LEGACY_CREDENTIAL_DIRECTORY \
  --database /var/lib/private/mail-bridge-rust/mail-bridge.sqlite3 \
  --owner-file /etc/mail-bridge-rust/owner_password
```

迁移在一个 SQLite 事务中完成，保留账户 ID、地址、连接设置、密码和 SMTP 开关。
重复执行仅接受完全相同的账户；冲突会回滚，不覆盖已有账户。OAuth、订阅和发信
去重表均不改动。只有这一次性工具读取旧文件，服务本身完全不读取旧账户路径。

替换二进制及 systemd 单元，移除旧账户配置环境变量和凭据导入，新增配置页代理。
验证数据库账户与旧源逐项一致、原 OAuth 和去重记录完整，再把旧账户文件与旧
配置脚本移入受保护的回滚备份，避免留下活动的第二套账户来源。重新启动本次
升级后的服务，检查 discovery、未授权 MCP、账户列表及已有授权。迁移不登录邮箱，
不发送测试邮件。只有本次升级二进制需要重启，后续添加账户无需重启。

## 数据与回滚

数据库包含邮箱密码，未加密；目录 0700、文件 0600，备份同样按秘密保护。
服务单元保留 DynamicUser、私有 StateDirectory 和 ProtectSystem=strict，无需放宽
系统目录写权限。owner 密码仍是服务授权凭据，独立于运行时邮箱账户。

失败时保持服务停止，恢复备份的数据库、二进制、服务/代理配置及旧账户文件，
`systemctl daemon-reload`、检查 nginx 配置后再启动。旧文件在回滚备份中保留，
正常运行的服务不再引用它们。
