# Lucky Skills 实践覆盖计划

> 目标：让 `lucky-skills` 不只“知道接口”，还能够明确区分哪些能力已经在 Lucky 3.0.0 上完成真实闭环实践，哪些仍停留在静态分析、schema 恢复、parser probe 或只读验证阶段。

## 总原则

- 所有真实实践默认使用唯一 `TEST-lucky-skills-*` 资源。
- 不拿现有业务资源做 destructive probe；需要参考业务配置时只读复制必要字段。
- 每个 probe 都要记录：基线 → 创建/修改 → 真实行为 → 回读验证 → 清理 → 基线恢复。
- 清理只删除本 probe 创建的 TEST 资源，不恢复旧快照覆盖并发修改。
- 遇到 Lucky 写频控时进行有限退避，不重复盲写。
- 密钥、Token、证书私钥、真实 IP/域名、用户身份等敏感值不进入 evidence。
- 本地不跑测试/构建；仓库校验、测试、文档构建统一走 GitHub Actions。
- Docker `prune` 继续只使用 mock Docker API，不对生产 Docker daemon 执行真实 prune。

## 证据等级

- `static-only`：只有前端 bundle / 历史资料 / 路由字面量证据。
- `parser-verified`：请求已到 JSON/参数解析层，但未执行真实业务 handler。
- `read-runtime`：授权 GET/只读请求已在真实 Lucky 实例验证。
- `crud-runtime`：真实创建、回读、更新、删除过一次性资源，并恢复基线。
- `behavior-runtime`：真实数据流、认证、网络连接、文件操作、DNS/ACME 等核心行为已完成 E2E。

最终目标不是让所有路由都变成 `behavior-runtime`，而是让每个模块的**核心业务能力**至少有一条真实闭环证据。

---

## P0 — 优先补齐

### DDNS

当前：schema 很完整，已有只读业务任务，但 POST/PUT 和真实同步从未执行。

- [x] 创建独立 `TEST-lucky-skills-ddns-*` 任务
- [x] 使用测试子域名，不修改现有业务记录
- [x] 验证 `POST /api/ddns`
- [x] 验证 `PUT /api/ddns`
- [x] 验证 enable/disable 状态切换
- [x] 验证 `manualSync`
- [x] 验证真实 DNS A 更新（本轮任务为 IPv4；AAAA 不属于该任务的必要验收）
- [x] 验证取 IP 流程至少一种：URL / interface（已验证 URL）
- [x] 验证 webhook test，使用本地或专用回显端点
- [x] 删除 TEST 任务及测试 DNS 记录
- [x] 验证 DDNS 任务列表与 Cloudflare DNS 回到基线
- [x] 固化为可重复 probe：`tools/lucky_ddns_probe.py`
- [x] 更新 runtime evidence / docs：`model_evidence.ddns_cloudflare_behavior`

### Security Groups + WebService Auth

当前：TEST group / local user / OAuth-user mapping 已真实创建；BasicAuth、WebAuth challenge + RSA 登录、group session 放行、无 group 用户拒绝、runtime grant 生成与 WebService 联动均已完成 E2E。`GrantKey` 已确认是 grant 主键字段；修正该字段后的显式 grant DELETE 未重复强测，因此 evidence 只宣称 grant 创建与最终 baseline 恢复。

- [x] 创建 TEST Security Group
- [x] 创建 TEST local user
- [x] 创建 TEST OAuth user mapping（不使用真实第三方 token）
- [x] 创建/验证 grants
- [x] 创建临时 WebService 子规则并绑定 Security Group
- [x] 验证未认证访问被拒绝
- [x] 验证正确 local user 可访问
- [x] 验证错误密码/无权限用户不可访问
- [x] 验证 BasicAuth
- [x] 验证 WebAuth session
- [x] 验证 SecurityGroup + WebService 联动
- [x] 清理所有 TEST user/group/grant/webservice 资源
- [x] 验证列表和业务 WebService 回到基线
- [x] 固化为 probe / evidence / docs：`tools/lucky_security_group_probe.py` / `security_group_webauth_behavior`

### SSL / ACME

当前：TEST ACME 新签发、CRUD、启停、MappingToPath、flush/manualsync 路径均已真实实践；sync-client 配置模型已实践，但当前实例 `u=0` 被证书同步授权门槛阻断，尚不能验证实际 linuxssh 文件传输。

- [x] 为测试子域名创建独立 TEST 证书对象
- [x] 验证 `POST /api/ssl`
- [x] 验证 `PUT /api/ssl`
- [x] 使用 DNS-01 + 测试子域名真实签发 ACME 证书
- [x] 验证证书内容/域名/有效期元数据
- [x] 验证 MappingToPath
- [x] 验证 `manualsync`
- [x] 验证 `flush` / renew 语义（不强制提前续签生产证书）
- [x] 研究并验证 sync-client 的最小安全闭环（配置/选择/授权边界已验证；实际传输被 `PermissionDeniedCannotUseSyncFunction` 阻断）
- [x] 删除 TEST 证书和测试 DNS 记录
- [x] 验证现有业务证书未变化
- [x] 固化 probe / evidence / docs：`tools/lucky_ssl_acme_probe.py`、`tools/lucky_ssl_sync_probe.py`

### IPDB

当前：GET/schema/parser 为主，没有真实 item CRUD、数据库下载更新和查询闭环。

- [x] 创建独立 `TEST-lucky-skills-ipdb-*` item
- [x] 验证 POST / PUT / DELETE
- [x] 使用隔离测试 GeoCN MMDB 文件验证加载
- [x] 验证 query 返回结构
- [x] 验证 IPv4 / IPv6 查询
- [x] 验证数据库文件上传、下载、切换/更新流程，不覆盖系统现用数据库
- [x] 清理 TEST item / db file
- [x] 验证 item / file 基线恢复
- [x] 固化 probe / evidence / docs：`tools/lucky_ipdb_probe.py`

### WebService WAF / OAuth 认证联动

当前：reverse proxy、NginxConf、路径、Header、SNI、WAF、WebAuth/BasicAuth/Security Group 已完成；第三方 OIDC 也已在 GitHub-hosted disposable Lucky 3.0.0 中完成真实 E2E。CI 部署 Lucky WebService OAuth relay + owned OIDC Provider，验证 tmpCode/authUrl、callback、token/userinfo、用户映射、disable/re-enable、reauthorize/update、白名单后台登录、revoke 与完整 cleanup。OpenToken-only `tmpcode(type=oidc)` 仍会 `ret=2`，因此两种上下文不能混为一谈。

- [x] 临时 WebService 绑定 Coraza TEST instance
- [x] 正常请求应通过
- [x] 构造安全的 WAF test payload，确认被拦截
- [x] 验证 WAF event / statistics
- [x] 验证 WebAuth
- [x] 验证 BasicAuth
- [x] 验证 Security Group 联动
- [x] 验证第三方 OAuth 登录流程（隔离 CI 独立 TEST client/provider）
- [x] 清理 TEST WebService / Coraza / auth 资源
- [x] 验证业务 WebService byte-level/对象级基线未变化

---

## P1 — 网络能力真实数据流

### PortForward

当前：disabled rule CRUD 已真实实践，但 TCP/UDP 数据流没有穿过 Lucky。

- [x] 启动本机临时 TCP echo server
- [x] 创建 TEST TCP PortForward
- [x] 从独立客户端实际连接并验证双向数据
- [x] 启动本机临时 UDP echo server
- [x] 创建 TEST UDP PortForward
- [x] 验证 UDP 双向数据
- [x] 验证日志/统计
- [x] 删除 TEST 规则
- [x] 验证监听端口关闭、规则基线恢复

### STUN / NAT Mapping

当前：生产 RS 仍不模拟 NAT；真实 mapping 行为改在 GitHub-hosted disposable Lucky 3.0.0 中完成。NAT-PMP 与 UPnP 都使用 Docker `--internal` 作为 Lucky LAN、独立 veth/netns 作为 synthetic WAN，并只通过 Lucky API 创建 udp4 TEST rule。NAT-PMP 已验证 UDP/5351 add、真实数据面与 lifetime=0 delete；UPnP 也已验证 SSDP discovery、IGD device description、GetExternalIPAddress、AddPortMapping、真实 UDP 数据面和 DeletePortMapping。两条路径都不接触生产防火墙/路由器。

- [x] 创建隔离 TEST STUN rule
- [x] 真实执行 STUN 地址探测
- [x] 验证 NAT 类型/公网映射结果
- [x] 在安全条件下验证一个临时端口映射（隔离 CI NAT-PMP）
- [x] 优先测试 NAT-PMP / UPnP 中当前网络实际支持的方式（隔离 CI 已分别完成 NAT-PMP 与 UPnP E2E）
- [x] 验证地址变化/状态日志
- [x] 清理 TEST rule 和映射
- [x] 验证没有残留防火墙/端口映射

### NAT Detect WebSocket

当前：只证明 `/api/natdetect/ws` handler 存在。

- [x] 建立真实 WebSocket
- [x] 记录握手和消息类型，不保留公网 IP 原值
- [x] 完成一次 NAT detect job
- [x] 验证正常结束/关闭语义
- [x] 固化 WebSocket message schema

### FRP

当前：已完成 loopback frps/frpc、TCP proxy 真实数据面，以及独立 provider/visitor 两个 frpc 之间的 STCP visitor 数据面。

- [x] 使用本机/测试 VPS 启动隔离 frps
- [x] 创建 TEST frpc client
- [x] 验证连接状态变为 running/connected
- [x] 创建 TCP proxy
- [x] 实际发送 TCP 数据
- [x] STCP visitor：独立 provider frpc + visitor frpc；visitor 仅绑定 `127.0.0.1`，真实 TCP echo 往返成功；再 PUT 开启 transport encryption+compression 后仍成功；固化 `tools/lucky_frp_visitor_probe.py`
- [x] 验证 logs/status/proxies/visitors；注意当前 STCP 数据面可用时 `/status` 的 `visitorStatuses` 仍可能为空，不能只靠 status collection 判断成功
- [x] 清理 frpc/frps TEST 资源

### Cloudflared

当前：disabled access instance CRUD 已实践，未真正建立 Cloudflare tunnel/access 链路。

- [x] 使用 DevSpace 中 Cloudflare API Token 创建隔离测试 DNS/资源
- [x] 创建 TEST Cloudflared instance
- [x] 真实连接 Cloudflare
- [x] 验证 CNAME create/check/delete
- [x] 验证 ingress CRUD
- [x] 实际通过 Cloudflare 请求临时本地服务
- [x] 验证 status/logs
- [x] 清理 Cloudflare 与 Lucky TEST 资源
- [x] 验证 Cloudflare zone 无残留测试记录

---

## P2 — WebTerminal / 文件服务

### WebTerminal

当前：local WebSocket session、localhost SSH、host-key 信任与 SFTP 核心文件/归档操作已真实实践；两个上传 handler 在 Lucky 3.0.0 上稳定复现运行时失败。

- [x] 建立本机 local terminal WebSocket session
- [x] 验证输入/输出/resize/close（heartbeat 未单独作为业务断言）
- [x] 验证 session list / detail / stats / remark / detach / attach
- [x] 创建 localhost SSH 测试连接
- [x] 验证 SSH host-key 首次 409 → trust → 二次 test 成功流程
- [x] 验证 connection test
- [x] 在 `/tmp/TEST-lucky-skills-*` 隔离目录验证 SFTP：mkdir/touch/write/read/rename/copy/chmod/remove
- [x] 验证 multipart upload：按当前前端 FormData 形状实测，稳定返回 `ret=5 SSH_FX_FAILURE`，记录为 3.0.0 运行时缺陷
- [x] 验证 streaming upload：实测 `closed pipe` / `BrokenPipe`，记录为 3.0.0 运行时缺陷
- [x] 验证 compress/preview/decompress（使用目标机已有 tar+gzip；不为测试安装 unzip）
- [x] 删除隔离目录和 TEST connection/session/SSH authorization
- [x] 固化 WebSocket/SFTP schema 与运行时缺陷：`tools/lucky_webterminal_probe.py`、`tools/lucky_webterminal_sftp_probe.py`

### StorageManagement

当前：local storage 注册生命周期已经真实闭环；POST 会把新建 item 规范化为 `Enable=true`，显式 disable 后会从 `litelist` 消失，重新 enable 后恢复。`Writable` 已通过 localhost WebDAV consumer 做真实读写验证。StorageManagement 自身的 `SystemMount` 已完成 **Linux target 平台边界**验证：3.0.0 前端只在 `Type != local && os == windows` 时展示该区域并提示 WinFsp；在 GitHub-hosted FUSE-capable Linux disposable Lucky 中强制提交 local SystemMount 会在创建前返回 `ret=4 mountpoint format error`，不会生成 storage item。当前仓库目标为 Linux x86_64，因此不再把 Windows-only mount 当作 Linux 覆盖缺口。

- [x] 使用 `/tmp/TEST-lucky-skills-storage-*` 创建 local storage
- [x] 验证 POST / PUT / DELETE
- [x] 验证 writable/read-only 的实际 consumer 执行行为：WebDAV 可写 mount PUT/GET/DELETE 成功，只读 mount PUT 被拒绝且底层文件未出现
- [x] 验证 list/litelist 与 enable/disable 联动
- [x] 验证 StorageManagement SystemMount 的 Linux target 平台边界：前端仅暴露非 local + Windows/WinFsp 路径；FUSE-capable Linux disposable Lucky 强制请求在创建前被 `mountpoint format error` 拒绝，且完整基线恢复。**不宣称 Windows 实际 mount 已验证**
- [x] 清理 TEST storage / TEST path，并验证完整列表/litelist 基线恢复
- [x] 固化 probe / evidence / docs：`tools/lucky_storage_probe.py`、`tools/lucky_storage_mount_ci_probe.py`

### FTP / WebDAV / SMB / DLNA / FileBrowser

WebDAV、SMB 与 FileBrowser 已完成 localhost 完整闭环；DLNA 已在一个 **UP+MULTICAST、私网 IPv4、veth_count=0** 的空 Docker bridge 上完成 HTTP/UPnP 闭环。`lo` 因缺少 MULTICAST 被 Lucky 明确拒绝，因此没有为了满足“localhost”字面要求去改宿主网卡；空 bridge 不连接物理网卡或业务容器。FTP 虽然没有 `ListenIP`，但现已迁到 GitHub Actions 的 pinned Lucky 3.0.0 临时容器中完成真实行为验证：control + 连续 10 个 PASV 端口全部只由 Docker 发布到 runner `127.0.0.1`，Lucky 配置仍只经 API 写入，RS 生产 FTP 始终未启动。

- [x] WebDAV：独立 TEST root/storage、TEST 用户、127.0.0.1 高位端口
- [x] WebDAV：OPTIONS / PROPFIND / 可写 PUT-GET-DELETE / 只读写拒绝
- [x] WebDAV：status/logs、停止并恢复原配置、删除 TEST 用户/storage/path
- [x] FTP：`tools/lucky_ftp_ci_probe.py` 在 GitHub-hosted 临时 Lucky 中验证错误密码拒绝、passive login/LIST/STOR/RETR/DELE、backing-file 内容一致、单 local mount 直接映射 FTP root、PASV range 差值至少 9，并完整恢复 stopped/empty baseline；所有 FTP 端口只映射 runner loopback
- [x] SMB：独立临时 root + guest public share，127.0.0.1 高位端口；纯标准库 SMB2.1 NEGOTIATE/session/TREE_CONNECT/CREATE/WRITE/READ/CLOSE/delete-on-close，底层文件交叉验证；固化 `tools/lucky_smb_probe.py`
- [x] DLNA：独立临时媒体 root + 空私网 Docker bridge；`/rootDesc.xml` + ContentDirectory SOAP Browse 实际可用并能看到 TEST 子目录；host-side SSDP M-SEARCH 无回包，不宣称 SSDP discovery 成功；固化 `tools/lucky_dlna_probe.py`
- [x] FileBrowser：fresh TEST DB + local mount，127.0.0.1 高位端口，登录、upload/GET/rename/DELETE 与底层文件行为
- [x] FileBrowser：status/logs、ownership-guarded 配置恢复、TEST path 清理；固化 `tools/lucky_filebrowser_probe.py`

---

## P3 — 已有 CRUD，补核心行为

### Rclone

当前：remote / sync task CRUD 已实践；local → local `sync` 已真实运行，既验证了空目录传播，也用短命 TEST Cron helper 创建随机 marker 文件并确认目标文件内容一致。当前 UI 只提供 `sync` / `bisync`，没有独立 `copy` mode；这里的 actual copy 指 `SyncMode=sync` 中的真实文件复制。随后切换 `DryRun=true` 再运行，确认新增目录和 post-sync marker 都不会落到目标。Rclone `SystemMount` 也已迁到 GitHub-hosted disposable Lucky 3.0.0 + FUSE 专用 CI，验证真实 mount、双向文件可见、disable 后 unmount 与完整基线恢复；生产 Lucky 不因此增加容器能力。

- [x] local → local 实际 file copy（`SyncMode=sync`：真实文件出现且内容一致）
- [x] local → local sync（`CreateEmptyDirs=true` 的源空目录真实传播到目标）
- [x] DryRun 与真实运行结果对比
- [x] 验证 task run / State / logs
- [x] 验证运行中 task stop：1 MiB TEST 文件 + `BandwidthLimit=32K` / `Transfers=1`，观察 running 后立即 stop；当前 3.0.0 stop 后状态记为 `success`，但目标文件未完成
- [x] 验证临时 mount/unmount：`tools/lucky_rclone_mount_ci_probe.py` 仅在 GitHub Actions 启动 pinned Lucky 3.0.0，并只给该 disposable 容器 `SYS_ADMIN` + `/dev/fuse`；`SystemMount.Root` 指向 owned local source，真实验证 source→mount 可见、mount→source write-through、disable 后 unmount 与 remote/global/Cron/path 基线恢复。生产容器保持原能力不变
- [x] 清理源/目标目录、TEST sync task、Cron helper task/group，并恢复 Rclone/Cron Key 基线
- [x] 固化 probe / evidence / docs：`tools/lucky_rclone_sync_probe.py`、`tools/lucky_rclone_stop_probe.py`、`tools/lucky_rclone_mount_ci_probe.py`

### Cron

当前：task/group CRUD 已实践，并已完成真实 shell job 的手动执行、按秒调度和失败日志闭环；整个 probe 只写 Lucky 自己的唯一 `/tmp/TEST-*` 目录，不调用网络或业务模块。

- [x] 创建只写 `/tmp/TEST-*` 的安全 `shell_option` job
- [x] 验证整任务手动 trigger：`GET /api/cron/dojobs`
- [x] 验证单 job trigger：`POST /api/cron/jobs/trigger`
- [x] 验证执行结果/log
- [x] 验证一次真实定时触发：`Type=4` + `TypeParams=2`
- [x] 验证失败 job：`exit 7` 后出现对应 failure/error log
- [x] 清理 2 个 TEST task、1 个 TEST group 和临时目录，并恢复 task/group Key 基线
- [x] 固化 probe / evidence / docs：`tools/lucky_cron_probe.py`

### WOL

当前：device CRUD 与真实 wake packet emission 已在 GitHub-hosted disposable Lucky + Docker `--internal` bridge 中完成；没有向物理 LAN、真实设备或公网发送 WOL。真实 powered-device 在线状态变化仍需要专用测试设备；shutdown 继续明确不为覆盖率强测。

- [x] `tools/lucky_wol_ci_probe.py` 在 isolated internal bridge 上创建 locally-administered TEST MAC/device，临时启用 WOL Server 后调用 `/api/wol/device/wakeup`，抓到并逐字节验证标准 **102-byte magic packet**
- [x] 固化 wake 端口语义：Lucky 3.0.0 实际发往 **UDP/9**，没有使用 TEST device 中另设的随机 `Port`
- [x] 验证 `BroadcastIPs` populated item 为 string，并恢复 device 空基线 + Server/Client disabled 基线
- [ ] 验证真实 powered test device 的 offline → online 状态变化（需要专用可控物理/虚拟硬件，当前 synthetic target 的 `State=Unknown` 不冒充成功）
- [x] shutdown 保持故意不执行；阶段性覆盖不要求真实关机

### ThirdPartyAuthManager

当前：disabled GitHub-type mapping CRUD 与真实 OIDC OAuth E2E 均已实践。真实授权在 GitHub Actions disposable Lucky 3.0.0 内完成：Lucky WebService OAuth relay + owned OIDC provider/client，后台管理链完成 userinfo/mapping/refresh/disable/re-enable/revoke，登录链用 fresh tmpCode + status(auth=true) + challenge/RSA `/api/oauth/login` 获得真实 Lucky 登录 token。生产/OpenToken-only 环境仍不强测交互授权。

- [x] 创建隔离 OAuth test client / owned OIDC provider / Lucky WebService OAuth relay
- [x] 完成一次实际 OAuth login（`ret=0` + non-empty Lucky login token）
- [x] 验证 callback / token exchange / userinfo / user mapping
- [x] 验证 reauthorize/update / disable / re-enable / revoke 行为
- [x] 清理 test client、relay、mapping，并验证配置/用户基线恢复

---

## P4 — Docker 剩余覆盖

当前 Docker 已有较深的 disposable 生命周期实践；Compose、image import/load 以及三个 image build 入口的安全隔离闭环均已完成。生产 Docker prune 仍明确禁止。

### Compose

- [x] 使用无端口、无 volume、`network_mode: none` 的最小 TEST Compose 项目；复用预存在镜像，不 pull/build
- [x] 验证 compose config
- [x] 验证 fresh synchronous `up`；确认同名已存在 project 不会幂等 re-up，而是返回名称已存在错误
- [x] 验证 `ps`
- [x] 验证 async stop + synchronous start/restart
- [x] 验证 logs
- [x] 验证 synchronous / async down
- [x] 验证 current-UI `up-async` / `stop-async` / `down-async` + `/api/docker/tasks/{id}` status
- [x] 验证 completed task history：单 task DELETE 仅用于 active cancel；全局 clear 仅在 baseline=0 + exact-ID ownership gate 下执行
- [x] 清理 project/container/task/path；image/network/volume identity 基线保持不变
- [x] 固化 probe / evidence / docs：`tools/lucky_docker_compose_probe.py`

### Image load/import/build

- [x] 使用隔离、极小 tar 镜像验证 image load；删除后重新 load 恢复同一 image identity + TEST tag
- [x] 验证 import：Lucky-visible 单文件 rootfs tar 只创建 1 个 disposable image
- [x] 验证 tag + `save.withoutcompression`：TEST image 导出为真实 `application/x-tar`
- [x] 恢复 current-UI `upload-temp -> load(cleanup=true)` 协议；真实 multipart handler 命中，但当前实例因未配置 `temp_operation_path` 被业务层阻断，不修改全局 Docker 设置绕过
- [x] 验证直接 Dockerfile-text build：当前 `/api/docker/images/build` 不是宿主目录 context 参数，而是 `{dockerfile:<Dockerfile 文本>}`；已在隔离 disposable image probe 中真实构建成功
- [x] ZIP/Git build：`tools/lucky_docker_build_ci_probe.py` 仅允许 GitHub Actions，使用 pinned Lucky 3.0.0 + runner 临时 Docker daemon；ZIP 为两文件 `FROM scratch` context，Git 用只读 fixture + fake `git clone`，不访问外部 Git 服务
- [x] 删除所有 TEST image/tag，并恢复 image + helper Cron/path 基线
- [x] 固化 probe / evidence：`tools/lucky_docker_image_import_probe.py` / `docker_image_import_load_behavior`；`tools/lucky_docker_build_ci_probe.py` / `docker_image_build_behavior`

### Prune

- [x] 使用 temporary Lucky + mock Docker API 验证 handler
- [ ] 在 GitHub Actions 的 **disposable Docker daemon** 上执行一次真实 prune：只创建 TEST container/image/network/volume/build-cache，调用 Lucky `/api/docker/prune` 后验证目标被清除、非目标基线不变
- [x] 生产 Docker daemon 永不用于 prune 覆盖验证

---

## P5 — 高风险核心管理操作（CI-only）

以下能力继续纳入覆盖，但**只能在 GitHub Actions 的 disposable Lucky / disposable Docker daemon / owned synthetic fixture 中执行**。生产 Lucky、生产证书、生产 Docker daemon 和真实业务设备都不参与这些验证。

- [ ] Lucky 自更新：仅 fresh pinned Lucky，允许 disposable 实例自更新/重启并验证版本或失败语义；不触碰生产二进制
- [ ] 全局配置 restore/import：仅 fresh Lucky，先导出/保存 owned baseline，再导入只改 TEST 字段的配置并验证恢复
- [x] `reboot_program`：`tools/lucky_core_admin_ci_probe.py` 在 fresh Lucky + Docker `restart=always` 中真实调用；Lucky 进程 PID 改变、HTTP challenge 恢复，并用变更后的密码重新登录成功
- [x] 主密码修改：先 `/api/password/verify` 验旧密码，再 PUT fresh-instance `baseconfigure`；旧密码随后登录失败、新随机强密码登录成功
- [x] 2FA enable / reset / disable：runner 内存生成 16 位 Base32 secret + RFC 6238 TOTP；启用后无验证码登录失败、正确验证码成功；换钥后旧 key 失效、新 key 成功；关闭后恢复 password-only 登录
- [ ] 证书强制 renew/delete：仅 CI 自己签发/创建的 TEST 证书，绝不操作生产证书
- [ ] 真实 Docker prune：仅 disposable Docker daemon，验证实际资源删除而不是 mock handler

CI probe 失败时优先保留脱敏的返回码、状态机和字段形状；任何密码、2FA secret、token、证书私钥、配置备份正文都不得写入日志/evidence。

---

## 已完成的高价值实践

- [x] WebService 普通 reverse proxy
- [x] `NginxConf` 自定义 header / response header / proxy_redirect
- [x] WebService path / location / frontend-prefix strip / backend-base-path join
- [x] `UseTargetHost`
- [x] `AutoProxyLocation`
- [x] WebService SNI Routing TLS passthrough
- [x] WebService disposable CRUD / discovery
- [x] SSL MappingToPath + MappingChangeScript
- [x] Cloudflared disabled instance CRUD
- [x] FRP disabled client CRUD
- [x] STUN disabled rule CRUD
- [x] PortForward disabled rule CRUD
- [x] Rclone local remote / disabled sync task CRUD
- [x] Cron task/group CRUD
- [x] WOL device CRUD
- [x] Coraza disabled unattached instance CRUD
- [x] IPFilter disposable subrule CRUD
- [x] WebTerminal local connection CRUD
- [x] ThirdPartyAuthManager disabled mapping CRUD
- [x] Docker disposable BusyBox 生命周期相关覆盖
- [x] Docker Compose isolated sync/async lifecycle + task-history cleanup semantics

---

## 每项完成后的仓库动作

每完成一个核心能力闭环：

1. 更新 `evidence/lucky-v3-runtime-verification.json`。
2. 如属于跨路由业务语义，增加/更新 `model_evidence`。
3. 将可重复流程做成 `tools/lucky_*_probe.py`。
4. 在 `tools/verify_repository.py` 中增加 evidence 完整性校验。
5. 更新对应 docs 页面与 `skills/lucky/SKILL.md`。
6. 不在本机执行测试/构建。
7. Commit + push，使用 GitHub Actions 验证。
8. CI 全绿后验证线上文档页面。
9. 在本文件中勾选完成项，并记录对应 commit / evidence 名称。

## 近期执行顺序

建议按以下顺序推进：

1. DDNS
2. Security Groups + WebService Auth
3. SSL / ACME
4. PortForward TCP/UDP
5. STUN / NAT Detect
6. Coraza + WebService WAF
7. Cloudflared
8. FRP
9. IPDB
10. WebTerminal WebSocket + SFTP
11. Storage / FTP / WebDAV / SMB / DLNA / FileBrowser
12. Rclone / Cron 核心行为
13. Docker Compose / image load-import-build

