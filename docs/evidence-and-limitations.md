# 证据与覆盖范围

本页只说明三件事：证据来自哪里、哪些结论已经验证、哪些边界仍然存在。

## 证据等级

| 等级 | 含义 |
| --- | --- |
| `frontend-call` | 前端构建产物中同时发现接口路径和 HTTP 方法 |
| `route-literal-only` | 只发现路径字面量，方法或实际用途仍不确定 |
| `runtime-verified` | 已在获授权的 Lucky 3.0.0 实例上验证路由、方法或只读行为 |

手写文档中的“实测”表示真实实例验证；“前端推断”表示来自当前 v3 前端；历史源码只用于解释背景，不作为 v3 行为证明。

## 当前验证基线

| 项目 | 当前结果 |
| --- | --- |
| 目标版本 | Lucky 3.0.0 wanji / Linux x86_64 |
| 只读验证 | `/api/status`、`/api/info`、`/api/modules/list` |
| WebService 写入 | 已验证创建 → 回读 → 删除，测试后基线恢复 |
| WebService reverseproxy 语义 | 已验证完整父规则 `ProxyList` 写入模型、`NginxConf` Header/路径/重定向、Host/helper 字段与自动反代重定向 |
| 308 重定向 | 已验证 `RedirectType="308"`，GET / POST 均返回 308 |
| WebService SNI 分流 | 已验证 `WebServiceType="SNIRouting"`、`Domains` + `Locations`，公网 TLS 流量经 SNI 路由进入本地 TLS 服务 |
| SSL 证书映射 | 已验证 `MappingToPath` / `MappingPath` / `MappingChangeScript`，并确认映射文件随证书对象生成 |
| SSL / ACME | 已验证 TEST 证书真实签发、CRUD/启停、MappingToPath、flush/manualsync 路径；sync-client 实际传输被当前实例 `u=0` 授权等级阻断 |
| WebTerminal | 已验证 local WebSocket session、detach/attach、localhost SSH host-key 信任及 SFTP 核心文件/归档操作；两个 upload handler 已复现运行时失败 |
| Core admin（CI-only） | fresh Lucky 中已真实验证主密码修改、旧密码失效/新密码登录、全局 2FA 启用/换钥/关闭及登录门禁、`reboot_program` 进程切换与恢复后重新登录；任何凭据/TOTP 均不落 evidence |
| 配置 restore（CI-only） | fresh Lucky 中已真实验证 `GET /api/configure` 导出、multipart `POST /api/configure` 导入、`restoreConfigureKey` confirm 和 marker 状态回滚；配置 ZIP 仅存在 runner 临时内存/目录，不落 evidence |
| StorageManagement | 已验证 local storage POST/PUT/DELETE、启停与 litelist 联动；创建会强制变为 enabled，Writable 已通过 WebDAV consumer 做真实读写验证；SystemMount 对当前 Linux target 已完成平台边界验证：前端仅对非 local + Windows/WinFsp 暴露，Linux 强制请求在创建前以 `mountpoint format error` 拒绝 |
| WebDAV | 已验证 127.0.0.1 临时服务、TEST 用户、OPTIONS/PROPFIND、store mount 可写/只读权限、日志与完整配置恢复 |
| FTP | 已验证 GitHub-hosted 临时 Lucky 3.0.0、runner-loopback control/PASV 端口、错误密码拒绝、passive login/LIST/STOR/RETR/DELE、backing-file 校验与完整配置恢复；RS 生产 FTP 仍不启动 |
| WOL | 已验证 GitHub-hosted 临时 Lucky 3.0.0 + Docker internal bridge 上的真实 wake packet emission 与虚拟 powered target 状态变化：wake 前 `Unreachable`，精确 102-byte magic packet / UDP/9 后夹具启动固定 TEST IP/MAC，Lucky 回读 `Reachable` 且 `ReachableTargetList` 命中；shutdown 仍未实践 |
| SMB | 已验证 127.0.0.1 高位端口的 guest public share、SMB2.1 NEGOTIATE/session/TREE_CONNECT、CREATE/WRITE/READ/delete-on-close、runtime/logs 与完整配置恢复 |
| DLNA | 已验证空私网 Docker bridge 上的临时服务、local mount、`/rootDesc.xml`、ContentDirectory SOAP Browse 与完整配置恢复；host-side SSDP M-SEARCH 当前无回包 |
| FRP | 已验证 loopback frps/frpc TCP proxy，以及独立 provider/visitor frpc 的 STCP visitor；visitor transport encryption+compression 更新后真实数据面仍可用 |
| Rclone | 已验证 local → local sync 的真实文件复制、内容一致性、空目录传播、DryRun、running-task stop，以及 GitHub-hosted FUSE 隔离环境中的 SystemMount mount/write-through/unmount；当前 3.0.0 stop 后会标 `success`，但这不代表文件已完整传输 |
| Cron | 已验证 `shell_option`、整任务手动 trigger、单 job trigger、每 2 秒真实调度、失败日志与 task/group/path 清理闭环 |
| Docker Compose | 已验证 isolated fresh sync up/down、current-UI async up/stop/down task、ps/config/logs、start/restart、task-history ownership gate 与六类资源基线恢复 |
| Docker image import/load | 已验证极小 rootfs tar import、TEST tag、`application/x-tar` save、删除后 load 恢复同一 image identity；`upload-temp` handler 已实测但被未配置 `temp_operation_path` 的实例前置条件阻断 |
| Docker image build | 已验证 Dockerfile-text build；ZIP/Git handler 在 GitHub-hosted 临时 Lucky + 临时 Docker daemon 上真实构建 `FROM scratch` marker image，Git 使用本地 fake clone、不访问外部 Git 服务，最终 image baseline 恢复 |
| Security Groups + WebAuth | 已验证 TEST group/local/OAuth mapping、BasicAuth 三态、WebAuth challenge+RSA 登录、组成员 session 放行、无 group 用户拒绝、runtime grant 生成及业务 WebService 子规则无变化 |
| `UNKNOWN` 路由 | 当前默认合并目录为 0 |
| OpenToken 鉴权 | 安全入口 + `openToken` 请求头 |
| 状态接口限流 | 当前实例约 20 请求/秒 |

真实 OpenToken、安全入口、域名和业务配置不会写入仓库。

reverseproxy / SNI / 证书映射验证同样只保留通用字段语义和脱敏后的行为结论，不保存真实域名、规则 Key、后端地址、客户端地址、证书正文、私钥或 ACME 凭据。reverseproxy 探针通过唯一 TEST 子规则验证真实 HTTPS 回源、路径拼接、Header 和重定向行为，并在结束后只从最新父对象中删除自己的 TEST 子规则；SNI 流量验证包含真实外部 TLS/HTTP CONNECT 与 Git smart-HTTP 只读操作，以确认四层双向转发，而不是只依据 Lucky 的 `ret: 0`。

## 证据如何合并

Lucky Skills 使用两层证据：

1. [`lucky-v3-endpoints.json`](../evidence/lucky-v3-endpoints.json)：从前端构建产物提取的静态接口快照；
2. [`lucky-v3-runtime-verification.json`](../evidence/lucky-v3-runtime-verification.json)：脱敏后的运行时验证、风险覆盖和 schema 补充。

运行时证据只有在 **Lucky 版本** 和 **静态快照 SHA-256** 都精确匹配时才会合并。任一条件不一致，客户端会 fail-closed，而不是继续套用旧证据。

静态分析主要回答“接口在哪里”；运行时验证主要回答“方法是否存在、风险如何、字段形状是否可靠”。两者都不等同于 Lucky 官方协议定义。

## 当前覆盖情况

- merged catalog 中共有 **243 条 POST / PUT / PATCH**；
- **219 条**带请求体并生成 OpenAPI `requestBody`；
- 这 219 条中仅剩 **1 条**仍含未类型化顶层属性；
- 显式 response schema 已覆盖 **354 条**路由；
- response 侧未定型 `{}` 叶子已降到 **0**；request 侧仍有 **31** 个。

目前重点覆盖 DDNS、WebService、Docker、FRP、SSL/ACME、Security Groups、IPFilter/PortTrap、PortForward、STUN、WebTerminal、StorageManagement、WebDAV、FTP、WOL、SMB、DLNA、FileBrowser、Rclone、Cron、ThirdPartyAuth/OIDC，以及部分 Status、IPDB、Modules 等接口。高风险核心管理操作统一迁到 **GitHub-hosted disposable Lucky**：主密码修改、全局 2FA enable/key-replace/disable、`reboot_program`、配置 export/import/restore、自更新 failure semantic 都已完成真实行为验证，生产 Lucky 不参与。自更新 probe 使用官方 2.27.2 Linux x86_64 发布包验证 3.0.0 的危险 downgrade 边界：`/api/update` 成功解析并返回 `ret=0`，`/api/update/comfire` 也返回 `ret=0`，随后 HTTP 中断且 45 秒内不恢复；Docker 仍报告容器 running、RestartCount=0、ExitCode=0，因此该路径被记录为 **non-serving downgrade failure semantic**，而不是成功升级。Docker prune 也已迁入专用 private DinD：Lucky 只看到 disposable daemon 的 Unix socket，真实删除停止容器、unused network、anonymous volume 与 dangling image，同时保留运行中的保护资源。实测 3.0.0 的 `all=true` 不删除 tagged-but-unused image，BuildKit cache 也未减少，因此文档不把它等同于 `docker image prune -a`。第三方 OIDC 已在 disposable Lucky 3.0.0 中完成完整 OAuth E2E；Rclone SystemMount 已在 FUSE 专用 disposable 容器中完成真实 mount/write-through/unmount；StorageManagement SystemMount 则完成 Linux target 的 Windows/WinFsp 平台边界验证。需要 powered fixture 的 WOL online-transition 仍只走 CI synthetic/virtual fixture。

证书 destructive 路径也已从生产式边界迁出。`tools/lucky_ssl_destructive_ci_probe.py` 在 fresh Lucky 中自行生成 self-signed TEST 证书并以 `AddFrom=file` 导入；强制 `PUT /api/ssl/flush` 返回 `ret=1 / UnsupportedRefreshType file`，不会进入 ACME、不会改变指纹。随后对同一 owned Key 的真实 DELETE 返回成功并恢复空 SSL 基线。因此仓库现在明确区分：ACME TEST 证书上的普通 flush 行为、file 证书上的强制 refresh 拒绝语义、以及 CI-only destructive delete，生产证书不再用于这些覆盖验证。

StorageManagement SystemMount 与 Rclone SystemMount 不应混为一谈。`tools/lucky_storage_mount_ci_probe.py` 的成功结论不是“Linux mount 成功”，而是证明当前 Lucky 3.0.0 的 StorageManagement UI/后端把该能力限定在 Windows/WinFsp 产品路径：served frontend 的区域 gate 为 `Type != local && os == windows`，保存校验器本身不含 SystemMount 检查；即使 disposable Linux 容器已经具备 `SYS_ADMIN` 与 `/dev/fuse`，强制 local SystemMount API 请求仍在创建前被 `mountpoint format error` 拒绝，且 storage/litelist/Cron/path 基线全部恢复。只有以后建立受控 Windows Lucky + WinFsp + 非 local storage 测试环境时，才可以进一步宣称 StorageManagement 的实际系统挂载行为。

第三方 OIDC 现在同时保留两条证据：生产式 **OpenToken-only** 调用仍不能取得授权 tmpCode（`ret=2`），但 CI 中的合法 disposable Lucky 会话已经完整跑通真实 OAuth E2E。成功路径使用 Lucky 自己的 WebService OAuth relay 和 owned OIDC Provider，最终通过 fresh tmpCode、`status.auth=true`、challenge/RSA `/api/oauth/login` 取得非空 Lucky login token；所有 code/token/password/safe-entry 只存在 runner 内存/临时目录，不写入仓库。

Rclone running-task stop 也已单独实践：probe 只使用 1 MiB owned 本地文件和 `BandwidthLimit=32K` / `Transfers=1` 来延长到可观察的 running 状态，随后立即调用 stop。当前 Lucky 3.0.0 会返回 `ret=0` 并退出 running，但 post-stop `State.Status` 记为 `success`、`LastError` 为空，即使目标文件尚未完成，因此这个状态只能视作“已终止”，不能当作完整同步成功证据。

Rclone SystemMount 已从生产部署上的 **runtime-blocked** 边界升级为隔离 `behavior-runtime`。`tools/lucky_rclone_mount_ci_probe.py` 只允许在 GitHub Actions 启动 pinned Lucky 3.0.0；Docker 仅为该 disposable 容器增加 `SYS_ADMIN`、`/dev/fuse` 与 unconfined AppArmor，Lucky 的 remote/global/Cron/path 修改仍全部通过 HTTP API。实测确认本地 remote 的挂载源路径应放在 `SystemMount.Root`，而不是顶层 remote `Root` 或 `Params.LocalPath`；正确配置后 owned source marker 会从 mount point 可见，从 mount point 写入的第二个 marker 也会回到 source。随后通过 `/api/rclone/remotelist/option?enable=false` 真实卸载，删除 TEST remote，并恢复 Rclone global config、Cron task/group 与 TEST path 基线。生产 Lucky 仍保持无 `SYS_ADMIN` / `/dev/fuse` 的原能力边界。

## 已知限制

- 前端未调用的后端接口可能无法发现。
- 动态路径只能归一化为 `{param}`，真实参数语义可能未知。
- 静态分析不能可靠推导所有必填字段、错误码、事务语义或 WebSocket 消息格式。
- 路由存在不代表写请求一定安全，也不代表请求体 schema 已完全验证。
- 不同模块、镜像和 Lucky 后续版本可能改变接口集合和行为。
- WebSocket 已在 NAT Detect 与 WebTerminal 上完成真实会话验证，但并非所有 WebSocket 路由都已恢复消息协议；当前 stdlib helper 已支持 HTTP 101 后同一 TCP read 内紧跟首个 WebSocket frame 的合法情况。
- SSL sync-client 的配置、选择模型和授权拒绝已实测；当前实例 `/api/info` 为 `u=0`，`manualsync` 在真正 linuxssh 文件传输前返回 `PermissionDeniedCannotUseSyncFunction`，因此不能宣称 sync-client E2E 文件传输已完成。
- FTP 当前配置仍没有 loopback `ListenIP` 字段，因此 **RS 生产宿主不启动 FTP 做覆盖率测试**。真实 FTP 行为已改在 GitHub-hosted 临时 Lucky 中验证，control/PASV 端口全部经 Docker 只发布到 runner `127.0.0.1`；后续 FTP 回归也应保持这种 CI/专用隔离环境，而不是转回生产宿主。
- ThirdPartyAuth/OIDC 的 OpenToken-only `tmpcode` 入口仍不能替代完整交互授权；回归 E2E 应继续使用 disposable GitHub Actions Lucky + owned OIDC Provider/WebService OAuth relay，不把真实 IdP、生产用户或浏览器自动化引入覆盖测试。

因此，接口目录是**经过验证的操作依据**，不是上游兼容性承诺。

## 为什么不自动验证全部接口

Lucky 的接口包含删除容器、执行任务、重启、恢复配置、终端和文件写入等高风险操作，而且部分有副作用的接口使用 `GET`。

所以项目默认优先使用静态证据、未认证方法探针和只读请求；只有在实例所有者明确授权时，才会对新建的一次性测试资源做有界写入验证，并在完成后立即清理。

## 更新快照

拿到新版本前端资源后：

```bash
python3 tools/extract_lucky_frontend.py /path/to/lucky-js-assets \
  --version <版本号> \
  --output evidence/lucky-v3-endpoints.json

python3 tools/render_lucky_artifacts.py evidence/lucky-v3-endpoints.json \
  --markdown docs/generated/api-routes.md \
  --openapi openapi/lucky-v3.openapi.json

python3 tools/verify_repository.py
```

只要版本或静态快照发生变化，就必须重新审核运行时证据并更新绑定哈希；旧验证不会自动沿用。
