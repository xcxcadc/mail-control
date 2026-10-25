# 附件功能定向上线与回滚

`tools/rollout_upload_features.py` 用于已有生产安装的小范围更新，不执行 `install.sh`，不重启主机、整组 Mailu 或其他业务容器。必须在已解压且构建完成的候选版本目录执行。依赖服务器 Python 的 PyYAML，命令需要 root 权限。

## 先准备再上线

完成候选 UI 的操作验证后，在服务器执行只读预览：

```bash
python3 /tmp/mail-control-release/tools/rollout_upload_features.py \
  --release-root /tmp/mail-control-release
```

`--release-root` 必须传入本次真实解压目录，示例 `/tmp/mail-control-release` 不是固定位置。未传 `--apply` 时不会写配置、创建备份或重启服务；仅读取 Compose/挂载/实际容器模板、验证补丁形状并输出变更范围。

明确应用：

```bash
python3 /tmp/mail-control-release/tools/rollout_upload_features.py \
  --release-root /tmp/mail-control-release --apply
```

## 精确变更范围

- 保留 `/opt/mailu/docker-compose.yml` 内所有现有 service 及其配置，仅为实际 admin/webmail 服务增加指定只读覆盖挂载。YAML 序列化会调整注释/排版，但不重建其他 service 配置。容器 Compose 标签与生产单一文件不匹配时直接失败。
- admin：从现有容器提取 `/app/mailu/utils.py`，只对已识别的密码验证器准备覆盖。主机 `/opt/mail-control/overrides/mailu-utils.py` 挂到原路径。
- webmail：从容器实际 `php --ini` 发现 conf.d，仅挂载 `99-mail-control-upload.ini`；另挂 `/defaults/application.ini`、`/conf/nginx-webmail.conf` 两个现有模板，以及 `/data/_data_/_default_/plugins/mail-control-upload` 的嵌套只读插件目录（加上 admin 挂载，共五个）。插件目录固定 `root:root 0755`，三个资产固定 `root:root 0644`，满足 Snuffleupagus 对执行文件的属主和不可写要求，不关闭保护。保留模板变量、SSO 与现有插件。
- 使用已核实的 `/data` 宿主挂载 `/opt/mailu/data/webmail`；实际路径不符、目标文件缺失、未知同目标覆盖挂载存在时失败，不猜测目录。
- 正式上线明确初始化 Mail Control 与网页邮箱的双策略为 **单文件 12 MiB、合计 24 MiB、最多 12 个**；SMTP 200 MiB、单项硬上限 100 MiB。候选环境验收使用的 1/2/2 不会被复制到生产。已有生产策略先校验并记入备份，回滚时恢复；上线后仍可在后台修改。双策略文件为 0644；事件元信息目录沿用网页邮箱属主，插件执行文件则按上一项使用 root。
- 更新生成的 `/opt/mail-control/mail_control.py` 与 `mail-control-admin.conf`；现有 `mail-control.conf` 的两个代理块设为 HTTP 300 MiB、读写/请求体超时 300 秒、关闭请求缓冲。
- 网页邮箱 Nginx 模板设为单请求 128 MiB、FastCGI 读取 300 秒；PHP 上传/POST 上限 128 MiB、100 文件、512 MiB 内存。业务限制仍由可编辑策略实时控制。
- Postfix 持久 override 仅更新/添加 `message_size_limit = 209715200`，保留域副本 socketmap 和其他参数；运行态用 `postconf -e` 后 reload，不重建 SMTP 容器。
- 配置生效仅重建 admin/webmail（`up -d --no-deps --force-recreate --pull never --no-build <admin> <webmail>`）、重启 `mail-control` 服务、reload front Nginx 和 Postfix。不拉取或构建新镜像。

应用前执行 Compose `config --quiet` 和 front `nginx -t`；重建后再次检查 front 配置才 reload。不得把整组 `docker compose down/up` 替换进本流程。

## 备份清单

应用前创建 `/opt/mail-control/backups/upload-features-<UTC时间戳>/`，目录 0700，`manifest.json` 0600。每个原始文件记录存在状态、SHA256、mode/uid/gid，以及备份相对位置：

- 生产应用、Compose、两份 Nginx override、Postfix override。
- SnappyMail 运行 `application.ini` 与其上传插件前备份。
- 双份附件策略 JSON、已有插件三文件、四个新的宿主覆盖文件（若原先不存在，也记入清单）。
- 容器原始 `utils.py`、默认 `application.ini` 与 Nginx 模板额外保存为来源快照。
- 原 SMTP 运行态 `message_size_limit`、实际 admin/webmail 服务名、发布目录、部署状态、精确回滚命令。
- 插件目录原存在状态、mode/uid/gid；回滚还原原目录属主权限，新建目录仅在为空时移除，不递归删除其他文件。

部署失败会按 manifest 自动恢复原文件并仅定向重建 admin/webmail；原 SMTP 限制一并恢复。如果自动回滚本身失败，manifest 标为 `rollback-needs-attention` 并打印可执行的恢复命令，不宣称上线成功。

## 手动回滚

使用部署输出的 `ROLLBACK=` 精确命令，或指定对应备份：

```bash
python3 /tmp/mail-control-release/tools/rollout_upload_features.py \
  --release-root /tmp/mail-control-release \
  --rollback /opt/mail-control/backups/upload-features-实际时间戳 --apply
```

省略 `--apply` 可只读查看本次恢复文件列表。恢复前逐个核对 SHA256；还原原来不存在的新增文件时仅删除清单中的该文件。不会删除账号、邮件、上传附件、事件记录或其他容器数据。保留本次 release 目录和备份目录直至上线确认结束。

## 本地检查

```bash
python -m py_compile tools/rollout_upload_features.py
python -m unittest test_accept_storage_lifecycle -v
```

脚本不执行 SSH，也不自动推送 GitHub。执行生产命令由主代理统一安排，避免多个代理同时部署。

## 隔离候选的存储生命周期验收

`tools/accept_storage_lifecycle.py` 只访问已经启动的 loopback 候选 HTTP 服务，不启动服务或 SSH 连接。需在候选宿主机执行，`--fixture-root` 必须是候选 API 已允许扫描的专用临时上传目录，且路径位于 staging/candidate 目录之下。工具拒绝生产 18080、80、443 端口、非 loopback 地址、URL 凭据和重定向。

先创建随机测试临时文件，并通过真实 HTTP DELETE 验证最近上传保护：

```bash
python3 /tmp/mail-control-release/tools/accept_storage_lifecycle.py \
  --base-url http://127.0.0.1:18082/ \
  --fixture-root /opt/mail-control/staging/control/temp --phase prepare
```

输出 `manifest`、`ready_at` 和剩余保护秒数。保留输出并继续其他候选验收，让真实 ctime 保护期自然经过；不要通过回拨系统时间或 `utime` 绕过。至少五分钟后执行：

```bash
python3 /tmp/mail-control-release/tools/accept_storage_lifecycle.py \
  --base-url http://127.0.0.1:18082/ \
  --fixture-root /opt/mail-control/staging/control/temp --phase verify \
  --manifest /opt/mail-control/staging/control/temp/mail-control-acceptance-实际随机标识.json
```

尚未成熟时返回状态 `waiting_for_real_protection_age`、退出码 3，不触发删除；可用 `--max-wait 60` 允许最多等待 60 秒。验收阶段创建第二个新文件并再次证明它被保护，再通过真实 API 删除已经成熟的第一个文件，确认成熟文件物理消失且新文件保留。成功后仅清理第二个脚本自建文件及其 manifest。

删除前核对随机文件名、固定测试内容、SHA256、device/inode、size、mtime/ctime 和 API token 对应项；不请求邮件删除、不枚举正文、不删除其他上传文件。失败时保留测试文件与 manifest 供核对，不做批量清理。
