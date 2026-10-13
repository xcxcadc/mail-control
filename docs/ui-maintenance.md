# 界面、路由与部署维护

## 源码和构建

`src/mail_control.py` 保存邮件控制应用源码，`src/flow_shell.py` 保存只读身份与导航渲染，`ui/` 保存蓝白主题的 CSS、JavaScript 和导航资源。`tools/build_ui.py` 将主题资源整合进根目录的 `mail_control.py`；该文件是服务器直接运行的部署产物。`nginx/mail-control-admin.conf` 是完整的 Mailu 页面覆盖配置，也必须随同一版本发布。

修改应用或 UI 后，在仓库根目录执行：

```bash
python3 tools/build_ui.py
python3 -m py_compile mail_control.py
python3 -m unittest -v test_mail_control.py
```

浏览器回归全部使用本地仿真邮件和 API，不连接正式服务器：

```bash
npm install --no-save playwright
npx playwright install chromium
node test_ui_performance.cjs
```

GitHub Actions 在每次推送和 PR 时检查构建一致性、Python 业务回归、安装脚本语法和桌面/手机浏览器交互。测试不会自动部署；修改、验证、提交、推送是后续调整的同步流程。持续同步代码需要每次变更执行提交和推送，没有在服务器创建定时提交任务。

只在 `ui/` 中改样式而没有重新生成程序，不会更新正式部署的嵌入资源。直接编辑生成文件会在下一次构建时丢失修改。版本化的静态资源 URL 必须与配置引用保持一致，使升级后的浏览器读取新资源；邮件和账户接口不能套用静态文件缓存策略。

## 功能入口

| 功能 | 路由 | 行为 |
| --- | --- | --- |
| 全局邮件查询 | `/admin/mail-control/global/` | 查询本站全部邮箱的现有邮件；新邮件通过刷新进入列表 |
| 精确筛选 | `/admin/mail-control/api/global/messages` | 支持完整邮箱、域名、前缀；指定前缀必须同时指定域名 |
| 邮件正文 | `/admin/mail-control/api/global/message`、`/admin/mail-control/api/body` | 使用认证后的正文与附件接口；HTML 禁止脚本 |
| 全局删除 | `DELETE /admin/mail-control/api/global/messages` | 校验选中邮件后通过 Dovecot 删除，保持 IMAP 索引一致 |
| 邮件控制 | `/admin/mail-control/` | 单邮箱历史邮件查询、发件及手动黑白名单管理 |
| 自定义发件 | `/admin/mail-control/custom-send/` | 任意有效前缀加本站现有域名；预览和发送前验证 |
| 批量邮箱 | `/admin/mail-control/accounts/` | 按域名批量管理邮箱 |
| 邮件营销 | `/admin/mail-control/marketing/` | 任务列表、模板、联系人及定时任务 |
| 营销编辑 | `/admin/mail-control/marketing/task/` | 配置任务并预览正文 |
| 发件 API 管理 | `/admin/mail-control/marketing/?tab=api` | 创建和管理发件 API 密钥 |
| Rspamd | `/admin/antispam/` | 保持原 Rspamd 功能，采用独立页面及统一侧边导航 |

`/mail-control/` 是兼容入口。发件 API 的 `/mail-control/api/v1/send` 和 `/mail-control/api/v1/batch-send` 继续支持 API 密钥；页面菜单使用 `/admin/mail-control/` 前缀。

## 布局与交互

“秩序蓝白”覆盖扩展页面和 Mailu 原生页面。桌面全局查询显示左侧邮件列表及右侧阅读区；手机使用居中的自适应详情窗口。密码、自动回复、域名、用户、令牌、中继域、客户端设置保留原表单和提交逻辑。Rspamd 保留 RequireJS 和其原有请求，SnappyMail 保留其原模板和主题变量。

主题须在首帧生效，避免先绘制旧主题再由 DOMContentLoaded 切换。导航不得等待额外页面下载才确定主要布局，不得让 Rspamd 或嵌入页面再生成第二层侧边栏。新代码应避免重复加载导航样式和字体；优化缓存只针对版本化 UI 资源和 Rspamd 静态资源，不能缓存鉴权或邮件查询结果。

## 权限与验证

Mailu 原生登录、会话及表单权限保持上游行为。扩展页面和全局邮件接口仅允许全局管理员；登录普通用户不会因此获得全局邮件权限，当前应用拒绝未授权接口使用 HTTP 401。UI 资源可以供已登录用户读取，这不会授予业务接口权限。Rspamd 必须经过 `/internal/auth/admin`，客户端配置和 Webmail 继续经过用户认证。

生产验证以只读访问、邮件预览、筛选和 `dry_run` 为主。不得将取消删除确认算作真实删除成功，也不得把发件预览算作真实外部投递成功。功能写入验证应使用专门测试数据，并记录实测范围。

## 安装及回滚

本地安装使用完整源码目录：

```bash
python3 tools/build_ui.py
sudo bash install.sh --source-dir .
```

在线安装从同一 Git ref 获取生成程序和 `nginx/mail-control-admin.conf`。两个文件均在系统配置修改前下载并检查；本地配置不存在时不能退回旧的内嵌 Rspamd 菜单。`deploy.py` 保留 `nginx/` 目录结构上传配置，再调用本地源码安装模式。

安装脚本会备份旧应用、systemd 服务和覆盖配置，执行 Nginx、Dovecot及健康检查，失败后恢复本次替换的文件。现有 Rspamd 策略和 Dovecot 聚合文件夹配置步骤仍由原安装流程维护。更新 UI 不要求重启主机或整组 Docker 服务。

## 导航与加载状态

扩展功能页由服务端先返回完整导航、当前用户显示名和手机抽屉，再独立加载该功能的数据；浏览器无需下载 `/admin/domain` 来创建导航。`/sidebar` 只作为已认证片段端点保留，并使用 no-store。Rspamd 的 upstream 页面先通过 `/internal/auth/admin` 校验，然后由 Nginx 对 HTML 的 `<body>` 执行一次 `sub_filter`，直接注入相同的固定全局管理员菜单、蓝白样式与抽屉交互。Mailu 当前授权实现要求用户启用且为全局管理员，因此该固定菜单与 Rspamd 权限边界一致。Rspamd 菜单首帧不再请求 `/admin/domain`；用户显示名使用通用“管理员”，不缓存账号信息。

Rspamd 保留上游 RequireJS、统计和配置请求，主题脚本异步加载，不阻塞 Bootstrap 的 DOMReady 初始化。导航注入不使用 SSI，也不改动 Rspamd API 或邮件业务响应。嵌入场景隐藏导航且不占侧栏宽度；部署前执行 `nginx -t`，然后只热加载前端配置。
