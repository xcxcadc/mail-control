# 生产共机维护边界

## 用户要求（2026-11-01）

`96.9.214.30` 同时承载 Mailu / Mail Control、V2bX 和用户新增的 NekoPass 转发面板（`hajidishu/nekopass`）。后续邮局维护必须保留三项业务并独立操作。

2026-10-26 迁移清理时“只保留 V2bX 和邮局”的要求不再是当前完整业务清单，不能据此删除后续安装的 NekoPass。

## 操作范围

- 邮局部署、更新和回滚只操作实际核验过的 Mailu 项目、Mail Control 以及邮件专属服务和目录。
- NekoPass 与 V2bX 的程序、配置、数据库、端口、监听、证书、反向代理及服务生命周期不属于邮局维护范围。
- 禁止将整机 `docker system prune`、`docker volume prune`、所有容器停机、Docker/containerd 重启、重写防火墙或整机重启作为邮局常规维护步骤。
- 清理镜像、卷、目录前必须核实实际归属和依赖；不能只根据“非邮局”“未使用”或镜像年代决定删除。
- 部署前后记录受保护业务的 PID / 容器 ID、启动时间和必要的监听状态，确认没有被邮局操作重启或改动。只读检查不读取业务敏感内容。

## 隔离边界

独立服务、目录和端口可避免应用级操作相互干扰；同一服务器仍共享内核、磁盘、内存、CPU 和网络。不得承诺物理故障或资源耗尽时完全互不影响。任何资源限制或网络拓扑调整都必须先根据实际部署核实，不能为了“隔离”直接重建现有服务。

## 部署现状

2026-11-01 已通过只读 SSH 检查核实：

| 业务 | 部署和路径 | 维护边界 |
| --- | --- | --- |
| Mailu | Compose 项目 `mailu`，工作目录 `/opt/mailu`，网络 `mailu_default` | 仅明确指定该项目及所需邮件容器；公共入口 `mailu-front-1` |
| Mail Control | `mail-control.service`，`/opt/mail-control`，监听 `172.20.0.1:18080` | UI/API 代码更新通常只重启此服务 |
| 别名副本 | `mailu-domain-copy.service` | 只在邮件转发规则变更时操作 |
| NekoPass | `nekopass.service`，可执行文件 `/opt/nekopass/bin/nekopass` | 独立 systemd 服务，监听 TCP 7071 / 9443 |
| NekoPass 数据库 | `postgresql@14-main.service`，监听 `127.0.0.1:5432` | NekoPass 的 `Requires=` 明确依赖该服务，邮局维护不得停机或清理它 |
| V2bX | `V2bX.service`，工作目录 `/usr/local/V2bX` | 独立 systemd 服务，保留其现有监听和规则 |

以上业务当前监听端口没有冲突；NekoPass 不在 Mailu Compose 项目中。检查时根盘约使用 5.8 GiB / 20 GiB，可用约 14 GiB。PID 和运行时用量仅作为当次操作的比较基线，不是后续重启或删除的固定目标。

安装器历史上存在按通用 Compose 服务名自动寻找首个容器的逻辑。此共机环境部署时必须显式提供 Mailu 目录和 front 容器，并核实 imap/admin/antispam 的 Compose 项目标签均为 `mailu`；不要将自动发现结果当成归属证明。

未核实的新路径和服务不能当作删除或重启目标。用户后续新装的业务需重新更新清单，不能把这个时间点的清单当作全机清理白名单。
