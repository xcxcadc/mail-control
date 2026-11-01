# Production maintenance boundaries

The production host `96.9.214.30` is shared by Mailu/Mail Control, V2bX, and NekoPass (`hajidishu/nekopass`). The user explicitly requires independent operation and requires all future mail maintenance to preserve NekoPass and V2bX.

- The 2026-10-26 cleanup instruction to retain only V2bX and mail is historical. NekoPass was added later and is now a protected production workload. Never remove it as an unused or unrelated service.
- Scope mail commands to the verified Mailu Compose directory/project, exact mail container IDs, and exact mail systemd units. Do not select a service merely because it is the first container named `front`, `admin`, `redis`, or another generic name.
- Do not use host-wide Docker cleanup, bulk container stops/removals, volume pruning, or Docker/containerd restarts during mail maintenance. Do not delete images based only on age, dangling status, or an assumption that this host runs only mail.
- Do not change NekoPass/V2bX services, binaries, configuration, databases, volumes, ports, certificates, reverse proxies, firewall rules, or network interfaces as part of a mail change.
- `nekopass.service` explicitly requires `postgresql@14-main.service`; protect PostgreSQL as a NekoPass dependency, including its data and loopback listener.
- Do not reboot the shared server or flush/rewrite its firewall for a mail deployment. Avoid host-wide package upgrades or global resource limits as incidental mail work.
- Before a production change, identify the protected services' current PID/container ID and start time, relevant listeners, and storage paths. After the change, compare these and perform only the checks relevant to the change. Do not expose credentials, tokens, mail contents, or customer forwarding rules in logs or Git.
- Prefer a Mail Control restart or configuration reload of the specifically affected mail container. Shared host/kernel/disk/network failure remains a common dependency; do not claim that separate services eliminate host-level failures.
- Keep operational details in `docs/production-cohosting.md`. Persist any new protected cohosted workload before applying later cleanup or deployment instructions.
- The user requests subagents for the current and subsequent maintenance tasks. For substantial work, delegate independent implementation/verification areas, assign non-overlapping ownership, and integrate and test before production deployment. Do not skip real functional validation.
