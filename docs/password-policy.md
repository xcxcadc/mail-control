# 邮箱密码策略

按站点所有者要求，新增邮箱和密码修改允许自选非空密码，不再因为不足 8 位或泄漏库命中而拦截。确认密码必须相同；用户自己改密仍需验证当前密码。密码继续由 Mailu 原有 `bcrypt_sha256` 哈希保存，身份认证、权限与登录限流不变。管理员编辑邮箱时不填写密码仍表示保持原密码。

## 原因与修改范围

Mailu 2024.06 在 `mailu/utils.py` 的 `isBadOrPwned(form)` 中硬编码检查长度和隐藏字段 `pwned`。报错 `This password appears in ... data breaches` 来自此函数，不能仅通过隐藏红色提示解决。

`tools/configure_password_policy.py` 只替换这个已识别的函数，拒绝未知实现或重复定义；除该函数外保留原文件内容。新策略仅拒绝空密码，现有表单的必填、确认、权限和当前密码检查仍生效。前端 HIBP 隐藏字段不再影响策略；此补丁不修改密码哈希和账户数据。

源码依据：Mailu 官方 `2024.06` 分支 `core/admin/mailu/utils.py`、`ui/views/users.py`、`sso/views/base.py`、`ui/forms.py`。构建时核对的上游提交为 `eadb95a69eb58fd3a120f50916e0d24545b8ecc6`。升级镜像后必须从新镜像重新提取，不能沿用旧镜像的整个 utils.py。

## 持久化部署

以下操作只针对 Mailu admin 服务。先以实际生产容器查到的 `mailu/utils.py` 路径为准，不猜测镜像目录。

1. 从当前 admin 容器提取实际的 `mailu/utils.py` 到宿主备份目录。不要导入 `mailu` 查询路径，以免触发应用启动；可用 `find /app /mailu -name utils.py`。
2. 生成覆盖文件：

   ```sh
   python3 tools/configure_password_policy.py \
     --source /opt/mailu/backups/password-policy/utils.original.py \
     --output /opt/mailu/data/overrides/admin-password/utils.py \
     --backup-dir /opt/mailu/backups/password-policy
   ```

3. 在生产 Compose 已有的 admin 服务中新增只读 bind mount，目标使用步骤 1 得到的准确容器路径。保留所有现有环境变量、卷和其他服务配置。例如实际路径为 `/app/mailu/utils.py` 时：

   ```yaml
   services:
     admin:
       volumes:
         - /opt/mailu/data/overrides/admin-password/utils.py:/app/mailu/utils.py:ro
   ```

4. 仅重建 admin 服务以应用 mount，不重启整个 Docker 栈。检查当前 Compose 有效配置含该 mount，并检查 admin `/ping` 正常。
5. 使用独立测试邮箱提交一位密码与命中泄漏库的密码，确认可保存；确认空密码与不一致密码仍不通过。测试不使用或修改真实用户凭据。已有登录页面上之前 flash 的警告可能在下一次页面读取时消失，不应删除全站会话。

重复执行生成工具不会改写相同输出。原位覆盖需显式指定 `--in-place --backup-dir`；`--check` 只报告不写入。回滚时恢复之前的 Compose 卷配置，或将原文件放回同一覆盖路径并只重建 admin。不要直接删除正在被容器挂载的源文件。

## 本仓库扩展

批量建号入口 `create_batch_accounts` 使用非空校验，页面输入说明为“可设置任意非空密码”。该入口直接使用安全哈希创建用户，不经过 Mailu 原生表单。发布时还须核对原生 Mailu 校验补丁已应用，两处策略应保持一致。

验证命令：`python -m unittest test_password_policy -v`。工具测试覆盖短密码、泄漏字段、Unicode、空密码、仅目标函数变化、幂等、未知代码拒绝与备份保留。

以上测试不代表真实页面已验收。上线前在候选环境使用独立临时测试账号实际新增邮箱、修改密码、重新登录并验证空密码/确认不一致仍被拒绝；不改真实用户密码。操作证据与结果记录到 [发布验收清单](release-upload-checklist.md)。
