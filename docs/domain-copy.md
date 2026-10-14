# 域名通配别名与已有邮箱副本

Mailu 2024.06 原生优先解析真实邮箱，再解析别名。`%@domain` 是未建邮箱的 catch-all；它不会复制已存在邮箱的邮件。`tools/mailu_domain_copy.py` 是可选、独立的 Postfix socketmap，专门为“域名配置了 `%` 通配别名时，已有邮箱也收一份并复制到通配目的地”提供规则。它不修改 Mailu 源码或用户数据库，也不需要逐账号同步转发字段。

## 范围

- 仅查询 `domaincopy` map；已存在的真实 User 且主域存在 `wildcard=1`、`localpart='%'` 别名才返回结果。停用用户仍是 Mailu 的真实投递邮箱，因此同样保留原地址并复制；未建邮箱、精确别名以及其他通配模式均 `NOTFOUND`，交给原 Mailu map。
- 返回顺序为原收件地址、用户已启用的转发目的地、域名通配目的地，格式校验并去重。即使原用户 `forward_keep=False`，命中本规则后仍保留本地副本，源用户 Dovecot Sieve/自动回复因此继续执行。这是域名复制功能的明确行为。
- 支持 Mailu alternative 主域解析、`RECIPIENT_DELIMITER` 的扩展地址。扩展地址优先匹配同名真实 User，再查基础用户；alternative 返回主域地址，保持原 Mailu canonical 行为。合法 ASCII localpart 与 IDNA 域名可直接解析，其余地址交原 map。
- 循环检查覆盖已知的本地用户转发、精确/SQL 通配别名、去除扩展后别名优先级以及新域名副本规则。返回源邮箱或出现局部循环的额外目的地会被排除，保留本地副本；日志只记录原因，不记录地址、内容或密码。外部服务器的后续转发规则无法从本地数据库知道。
- 每查询新建 `mode=ro` SQLite 连接和只读事务，同一查询使用一致快照；下次查询自然看到新邮箱/别名修改。数据库、关键 schema、锁等异常返回 `TEMP`，不会以 `NOTFOUND` 静默跳过复制。

## 配置和部署顺序

Python 3.8+ 标准库，无第三方依赖。先运行 `python3 -m unittest test_mailu_domain_copy.py -v`。测试只创建临时 SQLite 和本机临时测试端口，不发邮件、不接触生产数据库。Linux 下第 12 项还验证不覆盖活动 UNIX socket，以及仅删除已拒绝连接的旧 socket。

默认使用 UNIX socket，便于沿用 SMTP 已有 `/overrides:ro` 挂载，不依赖容器 IP：

```ini
MAILU_COPY_DB=/opt/mailu/data/data/main.db
MAILU_COPY_SOCKET=/opt/mailu/data/overrides/postfix/mailu-domain-copy.sock
RECIPIENT_DELIMITER=+
```

服务运行命令为 `python3 /opt/mail-control/mailu_domain_copy.py`。服务创建的 socket 权限为 `0666`，仅放在专用于 SMTP 的挂载目录；不要将该目录通过网站公开。已有普通文件、符号链接、正在监听的 socket 都拒绝覆盖；启动只移除已证明拒绝连接的旧 socket。systemd 可用 `ProtectSystem=strict`，仅将 socket 目录加入 `ReadWritePaths`，数据库目录只读；`Restart=on-failure`。脚本不自动写服务单元或 Postfix 配置。

仓库提供 [systemd 单元](../systemd/mailu-domain-copy.service)。按实际 Mailu 路径调整后安装：

```sh
install -m 750 tools/mailu_domain_copy.py /opt/mail-control/mailu_domain_copy.py
install -m 644 systemd/mailu-domain-copy.service /etc/systemd/system/mailu-domain-copy.service
systemctl daemon-reload
systemctl enable --now mailu-domain-copy
```

在服务正常运行且本地查询验证通过后，Postfix 的持久 override 设置：

```text
virtual_alias_maps = socketmap:unix:/overrides/mailu-domain-copy.sock:domaincopy, socketmap:unix:/tmp/podop.socket:alias
```

必须把新 map 放在原 alias map 前面，并保留原 map。Mailu 启动脚本会通过 shell 写入 override，因此持久文件使用展开后的 socket 路径，避免 `${podop}` 被 shell 错误展开；实际路径用 `postconf -xh virtual_alias_maps` 获取。用容器内 `postmap -q address socketmap:unix:/overrides/mailu-domain-copy.sock:domaincopy` 分别检查真实源邮箱、随机未建地址、精确别名和目标邮箱。确认源邮箱结果含原地址与预期目的地，未建/精确别名无结果；然后才 `postfix check` 和 reload，不需要重启 Docker 容器。

TCP 是备选且默认关闭。设置 `MAILU_COPY_BIND=172.20.0.1`、`MAILU_COPY_PORT=18081`、`MAILU_COPY_ALLOW=实际SMTP容器IP/32`，必要时 `MAILU_COPY_SOCKET=` 可关闭 UNIX。TCP 白名单不可省略；容器 IP 变化时必须更新白名单。

协议支持一条连接多次 netstring 查询，请求上限约 10 KB、回复上限 100 KB、读写超时 5 秒、最多 64 个并行工作线程；错误回复为 `TEMP`/`PERM`，只查询 `domaincopy` 名称。

停用回滚时先从 `virtual_alias_maps` 移除新 map、保留 `${podop}alias` 并 reload，再停止独立服务。不要先停止服务而仍保留映射，否则 Postfix 将暂缓投递。
