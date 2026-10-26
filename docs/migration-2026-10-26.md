# Mailu migration — 2026-10-26

## Result

The production installation moved from `104.223.85.78` to `96.9.214.30`. Mailbox data, attachments, configuration, account password hashes, aliases, DKIM keys, TLS certificates, webmail state, custom Mail Control features, and service definitions were transferred directly between the two servers over SSH. No mailbox archive or migration data was staged on the operator workstation.

The user updated DNS; `postal.qnns.de` resolves to the new address. Source Mailu services and container automatic restarts are disabled to prevent simultaneous production instances. Source data remains available for recovery. The unrelated source containers were not restarted.

## Preserved installation

- 20 accounts, 6 domains, and 5 aliases at the final synchronization.
- Original Mailu/Redis image configurations and layers, transferred with Docker save/load. The destination Docker containerd store reports manifest IDs; their config digests match the source image IDs.
- Original application file SHA-256: `e5accb917c2c08fa7d71fbe4fc7c184dd956bfd0f0579ef1c1a6c68a33cdd160`.
- Mailu data: 1,826 regular files, 171,432,779 bytes before target startup. Full content manifests matched before services started. Certificates and Nginx overrides also matched.
- Anonymous SMTP queue and webmail overrides volumes are attached explicitly through `docker-compose.override.yml`.
- Python virtualenv rebuilt for Ubuntu 22.04 / Python 3.10 with the existing `bcrypt==5.0.0` dependency; application source unchanged.
- Updated source DNSSEC trust-anchor state was copied directly and persisted under `/opt/mailu/resolver-runtime`. This resolves the initial destination DNSSEC SERVFAIL / admin 502 without disabling DNSSEC.

## Destination cleanup and limits

At the user's request, removed container `c52c8676952a` (Emby), its image and business directory; removed and masked Komari; removed unused LXD snap packages. Retained V2bX, the Mailu stack, Mail Control, Docker, OS services, and the certificate renewal image. V2bX PID remained unchanged during migration.

System journal is capped at 150 MB on disk / 50 MB runtime. Each mail container uses JSON log rotation at 10 MB × 3 files. Cleared obsolete package lists, package cache, and old failed-login logs. Final root filesystem use was approximately 5.5 GiB of 19.2 GiB, with approximately 13.8 GiB available. Mail retention and attachment policies were not changed.

## Targeted acceptance

- All Mailu containers with health checks healthy; Mail Control and alias-copy services active.
- Valid HTTPS admin login and webmail redirects; actual browser displayed the public admin login page.
- Delivered a real MIME message with an attachment to the support mailbox; decoded body and attachment matched.
- Global message query found the test message. Authenticated status, storage, upload-policy, and global-query endpoints returned HTTP 200.
- Existing external mail delivery and alias-copy delivery appeared in destination Dovecot logs.
- Upload PHP limits remain 128M / 128M; alias socketmap order unchanged.
- Outbound TCP/25 connectivity to QQ and Gmail reachable. This is connectivity evidence, not external inbox acceptance.

Evidence is retained only on the servers under `/root/mailu-migration-20261026/`; secrets and mailbox contents are not committed to Git.

## Remaining external setting

The new IP has no public PTR record at verification time. The server provider should set `96.9.214.30 → postal.qnns.de`. Existing SPF for `99765.my.id` references the MX and `postal.qnns.de` and therefore follows the new A record. The previously reported QQ SPF rejection is not claimed resolved by this migration.

## Recovery

Keep the old server's stopped installation until the new service is accepted. Do not simply start the old stack after new mail arrives: first stop writes on the destination, synchronize the new data back, then restore source restart policies and services and switch DNS. This avoids losing mail received after cutover.
