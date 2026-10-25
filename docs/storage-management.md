# 后台存储管理

此模块仅管理 Mailu 邮件目录和管理员显式允许的专用临时上传目录。宝塔网站、Docker 卷、其他业务目录不在扫描和清理范围内。

## 配置

- 邮件根目录沿用 `CONFIG.mail_root` / `MAIL_CONTROL_MAIL_ROOT`。
- `MAIL_CONTROL_UPLOAD_ROOTS`：JSON 数组，填写 **SnappyMail 或扩展发件模块实际使用的专用临时上传目录** 的主机绝对路径。默认为 `[]`，不会猜测或清理系统 `/tmp`。例：`["/opt/mailu/data/webmail/_data_/_default_/temp"]`，此示例必须经生产实际路径确认后使用。
- `MAIL_CONTROL_WEBMAIL_STORAGE_ROOT`：SnappyMail 账号存储根，默认 `/opt/mailu/data/webmail/_data_/_default_/storage`。仅在此根下固定深度 1–4 发现名为 `.files` 的非符号链接目录作为临时附件根，不把账号存储根自身加入删除范围；`.gnupg`、`.smime`、`.sessions` 等隐藏目录不遍历。新账号的 `.files` 目录最多 10 秒后自动发现，不存在不报错。
- 不允许把 `/`、`/tmp`、`/var/tmp`、`/opt/mailu/data`、邮件目录及其父子目录加入临时清理范围；不允许重复、嵌套、符号链接目录。
- `MAIL_CONTROL_UPLOAD_DELETE_MIN_AGE`：临时文件保护秒数，默认 300；即使配置低于 300，仍至少保护 5 分钟。修改时间或状态变化时间处于保护期内的文件不能删除。

配置应写入 Mail Control 服务环境。临时目录需专门用于可丢弃的上传缓存；禁止将 SnappyMail 的账号配置、联系人、登录会话、Sieve、邮箱数据或整个 `_data_` 目录加入白名单。

## 接口集成

维护源码位于 `src/storage_manager.py`，由构建程序内嵌到部署程序。模块需要应用已有的 `CONFIG` 对象；不自行创建监听端口。两个接口均必须通过原有全局管理员授权：

### `storage_snapshot(query)`

`query` 可直接使用 `urllib.parse.parse_qs` 的结果，也支持普通键值：

| 参数 | 值 |
| --- | --- |
| `source` | `all`（默认）、`mail`、`temp` |
| `mailbox` | 完整邮箱，精确匹配；空表示所有邮箱 |
| `q` | 邮件文件名、临时文件名、相对路径或邮箱的包含搜索；不搜索邮件正文 |
| `offset` | 分页偏移，默认 0 |
| `limit` | 每页 1–100，默认 25 |
| `refresh` | `1` 请求后台重新扫描 |
| `attachments` | `1`（默认）读取本页邮件的受限元信息；`0` 不读 MIME |

返回 `items / total / offset / limit / scanning / updated_at / started_at / error / partial / summary / roots / refresh_seconds / delete_min_age`。

- 首次请求立即返回 `scanning=true`，前端显示“扫描中”并轮询，不能显示“没有文件”误导用户。首次扫描完成后有 `updated_at`。
- 快照默认有效 10 秒；过期请求使用已有快照并触发后台更新，不阻塞 API。刷新去重，每组目录同一时间只运行一个扫描线程。
- 扫描最多访问 250000 个目录项、持续 30 秒、嵌套 32 层。达到上限时 `partial=true`，前端必须显示“部分统计”，不能宣称覆盖完整。
- `summary.sources.mail/temp` 含 `bytes/files`；`summary.disks` 含所在磁盘 `total/used/free/used_percent`。同一磁盘只报告一次。磁盘用量包含整块磁盘其他业务，来源统计只包含受管文件，二者含义不同。
- 所有文件按修改时间降序。目录不存在时显示该上传 root `exists=false`，不创建或清理目录。
- `webmail_storage` 返回 `{path,exists,discovery_partial}`；发现目录本身有独立的 0.5 秒、20000 目录项及 2000 `.files` 根上限，达到上限会标记部分统计。

邮件项：`source=mail, mailbox, id, folder, path, filename, size, mtime, delete_mode=message`。这三项身份信息 `{mailbox,id,folder}` 可直接交给现有 `delete_global_messages({"messages":[...]})`，由 Dovecot 根据 UID / mailbox GUID 删除并维护配额；**绝不能用 `path` 直接 unlink Maildir**。

邮件元信息读取限于本页每封前 256 KiB，避免为列表完整读取大附件。返回 `subject/from/date/attachments/attachment_state/attachments_note`。`attachment_state=partial` 表示只读到前段 MIME，可能还有附件未列出；此时前端提示“附件信息未完整展开”。附件大小为 `null`，不把截断片段估算成完整大小。邮件 `size` 是完整原始 MIME 文件大小。需要完整正文/附件时沿用现有邮件详情接口。

临时项：`source=temp, root_id, path, filename, size, mtime, delete_mode=temp, token, deletable, delete_reason`。`deletable` 仅表示已通过快照时的保护期判定；真正删除仍会核对身份、活跃使用和目录。前端不应把删除按钮用于没有有效 token 的项。

SnappyMail 真实路径为 `storage/<domain>/<local>[/<additional-email>]/.files/<hash>`，可推导主邮箱或额外邮箱地址。哈希文件名不一定保留原附件名，因此 `filename_note` 明确标记“网页邮箱临时文件标识（原附件名未映射）”，不要把该标识展示为原附件名称。

### `delete_storage_temp(payload)`

```json
{"confirm": true, "tokens": ["来自当前快照的 token"]}
```

每次 1–100 个 token。需要前端明确确认，接口不支持“删除全部”或自动清理。返回 `{deleted:[{token,filename,size}], errors:[{token,error}]}`，允许部分失败并逐项反馈。

- token 使用进程内随机密钥 HMAC，绑定根目录、相对路径、inode/device/大小/纳秒修改时间/状态时间，1 小时过期；服务重启后旧 token 失效，刷新即可。
- 目录不在当前白名单、路径越界、文件变动、文件已删除、符号链接、最近上传文件均拒绝。
- Linux 下检查 `/proc/*/fd`，仍被进程打开的文件拒绝删除；不能确认时保守返回错误。删除时通过 `dir_fd` 和 `O_NOFOLLOW` 限制路径，防止中间目录被替换为符号链接后越界。
- Windows 为本地开发路径，使用再次校验的普通 unlink；生产 Linux 使用上述目录描述符路径。
- 不删除邮件、不改用户配额、不自动清空正在上传的数据、不改其他业务数据。
- 邮件附件属于 MIME 内容，并非独立可清理缓存。删除邮件会同时删除全部正文与附件，UI 应明确写“删除整封邮件（含附件）”。

## 聚焦验证

`python -m unittest test_storage_manager -v` 覆盖分页/精确邮箱筛选、MIME 截断标注、异步扫描去重、保护期、内容变更和活跃上传保护、篡改/过期 token、目录白名单、符号链接/越界、普通邮件保留。
