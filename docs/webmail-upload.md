# 网页邮箱统一附件策略

SnappyMail 2.38.2 使用公开插件接口安装 mail-control-upload，不修改压缩应用 JS、PHP 核心或全局 XHR。

## 安装和配置

在服务器源码目录执行 python3 tools/configure_webmail_upload.py --data-root /opt/mailu/data/webmail --policy /opt/mail-control/upload-policy.json。

--data-root 必须是该容器实际挂载到 /data 的宿主目录。安装工具只合并 SnappyMail 的 plugins.enable、plugins.enabled_list 和 webmail.attachment_size_limit，保留已有插件与其他配置。初次变更保留 application.ini.before-mail-control-upload。插件资产及策略均保存在持久 /data。Mailu 启动会从 /defaults/application.ini 生成运行配置，因此还需把生成的 application.ini 作为专用宿主模板持久挂载到 /defaults/application.ini，只读；保持现有模板变量和代理认证设置。

策略文件 /data/mail-control-upload-policy.json 使用整数 single_mb、total_mb、max_count、message_mb。前三项范围 1–100，单文件不得大于总量；默认 12 MB、24 MB、12 个，MIME 邮件限制默认 200 MiB。后台保存后原子写入策略，每个 PHP 请求重新读取；打开中的写信窗口每 10 秒同步。策略刷新接口要求已登录网页邮箱。SnappyMail 单文件限制在每个上传请求中动态覆盖，正文内嵌图片同样计入发送限制。

HTTP、PHP 与 SMTP 传输限制必须覆盖业务限制：本部署 PHP upload_max_filesize=128M、post_max_size=128M、memory_limit=512M，Nginx 300 MiB、SMTP 200 MiB。可使用 --php-ini <独立覆盖文件> 生成 PHP 设置，然后在 Mailu Compose 中持久挂载到实际 PHP conf.d 目录。工具本身不重启容器、不更改 Compose、不改 SMTP。

## 进度和服务端防绕过

- 写信附件行显示进度条、实际 XHR 已传输/总字节、百分比及服务器处理阶段；100% 只代表网络上传完成，收到服务端成功回执后显示附件已就绪。
- 插件只包装该写信窗口现有 Jua 实例的事件，继续复用 SnappyMail 原上传、取消和错误处理。
- 选择文件时检查数量、单文件与累计大小；失败不会开始上传。发送前再次检查。
- 服务端每次上传按全局单文件限制校验；发送前从 FilesProvider 读取真实临时文件大小，核对数量、总量、内嵌图片；再检查 MIME 资源与实际 SMTP 流大小，不信任浏览器提交的 size。

## 后台存储关联

上传成功只写 /data/mail-control-upload-events/<sha256容器绝对路径>.json 元数据：source,path,filename,mailbox,size,mtime。mtime 使用实际附件 filemtime，目录权限 0700、文件 0600，不保存邮件正文或附件副本。后台扫描器根据 .files 文件的真实存在情况关联显示，删除后过期元数据不代表仍占有附件空间。

上传过程通过已登录账户的官方 MailControlUploadProgress JSON hook 每秒最多一次异步上报，单写信窗口最多一个请求在途。进度元数据文件名为 progress-<sha256(account+NUL+clientid)>.json；字段为 id、source=webmail、actor、total、received、status、files=[{filename,size}]、error、created_at、updated_at、reported_by=client。服务端绑定真实登录账号，限制数值 0–128 MiB、received≤total、id格式及状态；该数据仅作后台观察，不用于权限、大小校验、配额计费或删除依据。网络进度代表浏览器上传字节，不代表SMTP投递成功。仅进度 JSON 自动保留24小时、最多1000个，清理不会触碰附件或邮件。

SnappyMail 文件实际位于 _data_/_default_/storage/<域名>/<本地部分>[/<附加账号>]/.files/<sha1>。storage 同时含账号设置等业务数据，不得将整个 storage 设为可删除根目录；只注册逐个 .files 目录，并由后台校验路径、防符号链接、保护活动文件。邮件内 MIME 附件归属邮件文件，清理临时上传与删除整封邮件是不同操作。

## 聚焦验证

- python -m unittest test_webmail_upload -v
- node --check webmail/mail-control-upload/upload.js
- node webmail/test_upload.cjs
- php webmail/test_policy.php

PHP 测试使用临时稀疏文件，无生产账户、邮件或实际发送；JS 模拟原 Jua onSelect/onProgress/onComplete 流程，核对真实 progress 事件、错误状态及限制时不上传。
