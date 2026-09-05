# Mailu 邮件中控

这是一个为 Mailu 提供管理能力的独立扩展，不是 Mailu 官方仓库，也不包含 Mailu 上游源码。

主要功能：

- 跨 Maildir 文件夹查询历史邮件
- 查看 HTML 和纯文本邮件
- 管理发件人黑名单和白名单
- 支持内嵌图片、图片链接、抄送、密送和附件的富文本发信
- 按域名批量创建和删除邮箱
- 邮件营销、联系人分组、模板、定时发送、限速和打开/点击统计
- 管理发件 API 密钥，支持单封和批量发信

## 部署

程序默认使用以下 Mailu 数据路径：

- 邮件目录：`/opt/mailu/data/mail`
- 数据库：`/opt/mailu/data/data/main.db`
- Rspamd 覆盖配置：`/opt/mailu/data/overrides/rspamd`

### 一键安装

请在 Mailu 所在服务器上以 root 身份执行。安装脚本会读取正在运行的 Docker Compose 容器挂载，自动识别 Mailu 目录、邮件目录、SQLite 数据库、Rspamd 配置、前端配置和 Docker 网关：

~~~bash
curl -fsSL https://raw.githubusercontent.com/xcxcadc/mail-control/master/install.sh | sudo bash
~~~

脚本可以重复执行，用于升级程序；每次执行都会校验 Nginx 配置和服务健康状态，并将替换的文件备份到 `/opt/mail-control/backups/`。安装不会删除已有邮件、邮箱或数据库数据。

如果无法自动识别 Mailu 挂载，脚本会在修改前停止，并提示需要传入的参数，例如 `--mail-root`、`--db` 或 `--override-dir`。后续校验失败时会自动恢复本次生成的文件。

自定义 Mailu 路径：

~~~bash
curl -fsSL https://raw.githubusercontent.com/xcxcadc/mail-control/master/install.sh | sudo bash -s -- --mailu-dir /srv/mailu
~~~

使用本地源码离线安装：

~~~bash
sudo bash install.sh --source-dir .
~~~

### 通过本地电脑部署

部署工具默认使用 SOCKS5 代理 `127.0.0.1:10808`。请先安装 Python 依赖，再通过环境变量或命令行参数提供连接信息。密码只在本地环境变量或交互式提示中使用，不要写入源码：

~~~powershell
$env:MAIL_CONTROL_HOST = "server.example.com"
$env:MAIL_CONTROL_SSH_USER = "root"
$env:MAIL_CONTROL_SSH_PASSWORD = "<服务器 SSH 密码>"
$env:MAIL_CONTROL_SOCKS_HOST = "127.0.0.1"
$env:MAIL_CONTROL_SOCKS_PORT = "10808"
python deploy.py
~~~

`deploy.py` 会将源码上传到远程临时目录，并调用同一套 `install.sh`。Windows 下也可以使用 `deploy.ps1`，它会自动准备 `paramiko`、`PySocks` 和 `bcrypt`：

~~~powershell
.\deploy.ps1 --host server.example.com --socks-port 10808
~~~

可选参数包括 `--mailu-dir`、`--front-container`、`--bind` 和 `--port`，也可以使用对应的 `MAIL_CONTROL_REMOTE_*` 环境变量。安装结束后远程临时目录会被删除。

## 功能入口

Rspamd 页面内置“中控菜单”，包含邮件控制、批量邮箱、邮件营销和发件 API。点击后会在当前页面的弹窗中打开，并复用当前 Mailu 登录状态，不需要二次登录。

原 `/mail-control/` 地址会跳转到 `/admin/mail-control/`。直接访问扩展接口或进行故障排查时，仍支持 Basic Auth。

Mailu 原生登录和会话路由保持不变，桌面端和手机端继续使用 Mailu 自带的 Cookie 和跳转逻辑。客户端设置页面及 Apple 配置文件下载需要 Mailu 用户登录；扩展页面和 Rspamd 页面继续执行各自的登录校验。

安装脚本还会提供 IMAP 聚合文件夹 `virtual.全部邮件`。它只读取现有物理文件夹，不移动、复制或删除邮件，网页邮箱和手机 IMAP 客户端都可以通过该文件夹查看完整邮件。

## 邮件营销和发件 API

邮件营销入口为 `/admin/mail-control/marketing/`，支持创建任务、HTML 模板、联系人导入、定时发送、限速、逐收件人进度以及打开/点击统计。营销数据单独保存在 `/opt/mail-control/marketing.db`，不会修改 Mailu 邮件目录和 `main.db`。

发件 API 页面生成的密钥只显示一次，请立即保存。接口地址：

~~~text
/mail-control/api/v1/send
/mail-control/api/v1/batch-send
~~~

请求示例：

~~~json
{
  "from": "sender@example.com",
  "to": "recipient@example.net",
  "subject": "通知邮件",
  "text": "纯文本内容",
  "html": "<p><b>HTML 内容</b></p>"
}
~~~

请求头支持 `X-API-Key: mc_live_...` 或 `Authorization: Bearer mc_live_...`。批量接口使用 `recipients` 数组；HTML、抄送、密送、回复地址和 Base64 附件使用与后台发信表单相同的字段。

## 安装后的地址

- 邮件控制：`/admin/mail-control/`
- 批量邮箱：`/admin/mail-control/accounts/`
- 邮件营销、模板、联系人和 API：`/admin/mail-control/marketing/`
- 发件 API：`/mail-control/api/v1/send` 和 `/mail-control/api/v1/batch-send`
- Rspamd 中控菜单：邮件控制、批量邮箱、邮件营销和发件 API

如果自动识别不适用于自定义部署，请使用 `--mailu-dir`、`--front-container`、`--bind`、`--mail-root`、`--db`、`--rspamd-dir`、`--dovecot-dir` 和 `--override-dir`，或设置对应的 `MAIL_CONTROL_*` 环境变量。

## 测试

~~~powershell
python -m unittest -v test_mail_control.py
~~~

## 安全说明

- 不要提交 `.env`、SSH 密码、API 密钥、Token 或私钥。
- 批量删除会保护全局管理员账号，但选中的普通邮箱及其邮件目录可能会被删除。
- HTML 邮件在禁用主动内容的沙箱框架中渲染。
