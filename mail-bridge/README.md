# Mail Bridge — HTTP MCP 邮件连接器

一个单账号、自托管的 HTTP MCP 服务。Python 3.11+，实际测试运行时为 CPython 3.12.14，**第三方运行依赖为零**。只交付 HTTP 这一版；源码可直接运行，也可放在支持 IMAP/SMTP 出站 TCP 的远程 Linux 主机上运行容器。

尚未部署、接入邮箱、创建账号侧插件或发送邮件。没有配置真实凭据。

## 功能

| 工具 | 行为 |
| --- | --- |
| configuration_status | 检查配置、凭据是否存在，不连接邮箱、不返回凭据 |
| list_folders | 分页列文件夹，解码 IMAP 中文文件夹名 |
| list_messages | 最新 UID 优先，每页最多 50 封，只取有限长度邮件头 |
| search_messages | 按 SUBJECT / FROM / TO / TEXT 搜索，支持服务器 UTF-8 搜索 |
| read_message | 读取 MIME 纯文本，HTML 转文本，最多下载 2 MiB，正文最多 20,000 字符 |
| prepare_draft | 预览明确的收件人、主题、正文；不发送，也不写入邮箱草稿夹 |
| send_email | 明确的写操作，需完整内容、唯一 request_id、confirm_send=true，以及本机配置启用 SMTP |

IMAP 使用只读 SELECT（EXAMINE）和 BODY.PEEK，不设置已读标志，不删除或移动邮件。邮件标识为 **文件夹 + UIDVALIDITY + UID**。翻页时传回同一 UIDVALIDITY 和 next_before_uid；UIDVALIDITY 改变会拒绝旧 UID。中文搜索如果服务器不支持 UTF-8，会明确失败，不静默返回错误匹配。不下载附件、不执行 HTML、不加载远程图片。大邮件请使用常规邮箱客户端。

## 1. 本人手动配置，无需把密码交给聊天

复制 `config.example.json` 到**项目和部署包之外**的私有目录，例如 Linux 的 `/opt/mail-bridge-private/config.json`。只修改邮箱地址与服务器配置；不要在 JSON 中加入密码。QQ 模板为 IMAP `imap.qq.com:993` 和 SMTP `smtp.qq.com:465`，均为 TLS。账号通常使用完整邮箱地址，密码使用本人在 QQ 邮箱设置中获得的客户端授权码。是否启用 IMAP/SMTP、是否申请授权码，由本人决定；本项目没有执行这些操作。[QQ 官方帮助](https://service.mail.qq.com/detail/0/75)

私有目录只允许本人/服务账号访问，配置文件应为 `0600` 或等价 Windows ACL。容器内 UID 10001 需要只读访问挂载的配置；按主机实际 UID/ACL 配置，不要为解决权限问题把配置改为所有人可读。

其他邮箱可改主机、端口，`*_security` 只能为 `tls` 或强制 `starttls`，不提供明文或跳过证书验证。服务器用户名与发件地址应为同一已授权账号。SMTP 默认 `false`，需要发信时本人改为 `true`。

Linux Bash 安全输入示例（输入不显示、不进入命令历史；实际秘密不写进脚本）：

```bash
export MAIL_BRIDGE_CONFIG=/opt/mail-bridge-private/config.json
export MAIL_BRIDGE_PUBLIC_URL=https://mail.example.com
read -r -s -p 'Mailbox authorization code: ' MAIL_BRIDGE_PASSWORD; printf '\n'
export MAIL_BRIDGE_PASSWORD
read -r -s -p 'Strong owner password (32+ ASCII characters): ' MAIL_BRIDGE_HTTP_TOKEN; printf '\n'
export MAIL_BRIDGE_HTTP_TOKEN
```

`MAIL_BRIDGE_HTTP_TOKEN` 在 OAuth 模式下是**服务所有者的独立授权密码**，不是邮箱密码，也不是客户端 access token。必须使用 32 字符以上的高强度 ASCII 随机值，不要与邮箱授权码相同。可在自己的密码管理器生成，手动输入。不要把任一秘密放进 URL、代码、Dockerfile、聊天、终端输出或版本库。环境变量对同主机管理员和 Docker 管理员可见；此单用户部署需要可信主机管理员。长期运行时应使用你现有的私密服务配置/secret 注入机制，不把实际值放进本包。

Windows PowerShell 可用 `Read-Host -AsSecureString` 本机手动输入，并在启动进程前转换为环境变量；不要粘贴真实值到脚本。HTTP 服务本身不提供远程修改账号或提交邮箱密码的工具。

## 2. 最简运行（二选一）

直接运行：

```bash
cd mail-bridge
python3 http_server.py
```

默认仅监听 `127.0.0.1:8080`。`PORT` 可改端口。去重日志默认在 Linux `~/.local/share/mail-bridge/send-attempts.sqlite3`（Windows 为 `%LOCALAPPDATA%/mail-bridge/`），也可通过 `LOCALAPPDATA` 指定持久数据根目录。

或 Docker Compose：在上述环境变量已安全输入的同一 Bash 中执行：

```bash
cd mail-bridge
docker compose -f compose.example.yaml up --build -d
```

只把 HTTP 端口映射到远程主机回环地址。配置从外部私有目录只读挂载；发送日志存入独立持久卷。镜像使用非 root 用户和只读文件系统。镜像标签固定为 `python:3.12.14-slim`，容器构建未在此 Windows 环境执行；生产环境可按自己的镜像审计流程固定 digest。不需要 `pip install`。

停止：`docker compose -f compose.example.yaml down`。**不要删除 mail-journal 卷**：日志是防重复发送所需的状态；删除后旧 request_id 将失去保护。

## 3. 给云端客户端接入

需要一个已指向该远程主机的域名与 HTTPS。设置 `MAIL_BRIDGE_PUBLIC_URL` 为该 HTTPS 域名的 origin（不带路径）。若主机已经有反向代理，把此域名上的 `/mcp`、`/.well-known/*`、`/oauth/*` 转发到 `127.0.0.1:8080`；也可在主机上按 `Caddyfile.example` 配置 Caddy，替换为自己的域名。代理保留 `Authorization`，**关闭访问日志，避免记录 OAuth code 查询参数**，也不记录请求体、Cookie 或认证头，并给邮件操作留足响应超时（建议 180 秒）。不要把 8080 明文端口直接暴露到公网。Caddy 的安装、DNS、证书和远程防火墙未在本次执行。

端点：`https://你的域名/mcp`。已实现 [ChatGPT 官方要求的 OAuth 授权流程](https://developers.openai.com/plugins/build/auth)：保护资源/授权服务器发现、公开客户端 DCR、授权码 + S256 PKCE、一次性 code、资源绑定、限时 opaque access token、轮换 refresh token、read/send scope 和工具级认证提示。ChatGPT 连接时选择 OAuth/DCR；不要求客户端配置自定义头或静态 API key。浏览器跳到你自己的服务页面后，核对请求权限与回调地址，再输入**独立的服务所有者密码**确认；**不要在这个页面输入邮箱授权码**。

服务声明 issuer identification，默认只允许官方稳定回调 `https://chatgpt.com/connector_platform_oauth_redirect`。若实际管理页给出不同回调，必须把管理页显示的**精确 HTTPS URI**加入 `MAIL_BRIDGE_OAUTH_REDIRECT_URIS` JSON 数组，例如在 Bash 中：`export MAIL_BRIDGE_OAUTH_REDIRECT_URIS='["https://chatgpt.com/connector_platform_oauth_redirect"]'`。不接受任意重定向。DCR 客户端的 token endpoint auth method 为 `none`，必须有 PKCE。实际云端 dot 的工具发现与账号插件连接需要部署后由父会话协调验证，尚未接通。

OAuth access token 有效期 1 小时，refresh token 30 天并轮换；数据库只保存 token 哈希、客户端、resource、scope 与有效期，不保存所有者密码。`mail:read` 用于读取/预览，`mail:send` 用于发送，启用 SMTP 仍是独立配置。此版本是**一个所有者、一个邮箱**，不提供多租户隔离。撤销全部 OAuth 连接：先停止服务，只删除持久数据目录中的 `mail-bridge/oauth.sqlite3`，再启动并重新连接；保留 `send-attempts.sqlite3` 以维持发信去重。仅轮换所有者密码不会自动吊销已发出的 OAuth token。

不设置 `MAIL_BRIDGE_PUBLIC_URL` 时，同一服务退回静态标准 Bearer 认证，供可配置 Authorization 的通用 MCP 客户端调试。**这个调试认证方式不能代替 ChatGPT OAuth 接入**；Compose 默认要求配置 PUBLIC_URL，避免误用。

实现 [MCP Streamable HTTP](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)：JSON-RPC POST `/mcp`，initialize、ping、tools/list、tools/call；通知 202；无 SSE 流时 GET 405；无 MCP 会话状态。POST 的 Accept 应含 `application/json, text/event-stream`。支持协商 2025-03-26、2025-06-18、2025-11-25；另实现 Sites 技能描述的 2026-07-28 `server/discover` 入口。工具定义固定，OAuth 模式附加每工具 securitySchemes。授权后的客户端可在 scope 内访问整个配置邮箱，因此只授权本人客户端，不分享所有者密码或 token。

Sites 托管运行时限制为 HTTP 外部连接、无原始 TCP，因此无法直接连接 IMAP/SMTP。这份服务须运行在你自己的 TCP 可用主机上；没有擅自接入其他托管商，也没有创建 Sites 或重复私有插件。

## 发信与重复保护

先用 prepare_draft 审阅明确的收件人地址、主题、正文，确认后才调用 send_email。`confirm_send` 是客户端传入的明确意图标记，服务端不能证明真人已经点过确认；客户端必须落实用户授权，且把 send_email 作为写工具处理。

每次用户授权的新邮件使用唯一 16–80 字符 request_id；同一发送请求保持相同 ID。SQLite 在任何 SMTP 网络操作**之前**持久记录尝试；重用同一 ID 不会再次发信，修改内容后重用同一 ID 会拒绝。仅保存请求 ID、内容摘要、Message-ID 和状态，不保存正文/收件人明文。超时、进程退出、部分收件人拒收、QUIT 失败等都可能使结果不确定；**不会自动重试**，也不要换 ID 绕过保护。先由本人核对邮件是否已到达。`accepted_by_smtp` 表示 SMTP 接受，不代表最终投递；此实现不通过 IMAP APPEND 自动保存“已发送”副本，邮箱服务是否显示副本取决于服务商。

## 本地验证（不需要邮箱）

```bash
python3 -m unittest discover -s tests -v
```

mock 覆盖中文 MIME/文件夹、UID 数字排序与 UIDVALIDITY、PEEK、搜索注入、正文/HTML 限制、发信控制、重启后去重、超时与部分接受。HTTP 测试只使用本机回环地址，验证鉴权、Origin、Accept、握手、工具发现、草稿工具、OAuth 元数据与权限拒绝；OAuth mock 验证本人确认、回调/资源白名单、PKCE、一次性 code 和 refresh 轮换。任何真实服务器兼容性、反向代理与实际客户端连接都需要在用户批准部署和邮箱访问之后验证。
