# 模块指南

本页解释主要接口族的用途和风险。精确方法、路径、查询字段与请求体提示见[自动生成路由表](generated/api-routes.md)。

## 核心与状态

常见只读入口：

- `GET /api/status`：进程、主机、内存、CPU、网络和连接概览；
- `GET /api/info`：版本、构建平台和已编译模块；
- `GET /api/modules/list`：运行时模块、显示名称与模块级验证状态；
- `GET /api/status/history`：历史监控数据；
- `GET /api/logs`、`GET /api/logscenter/query`：日志。

高风险入口包括基础配置修改、配置恢复、进程重启、进程终止和上传。日志可能包含域名、IP、路径和第三方错误信息，仍属于敏感数据。

## DDNS

`ddns` 接口族管理任务、记录顺序、凭据来源、手动同步、Webhook 测试、IP 获取脚本和 DHCP 客户端数据。

典型流程是先读取 `GET /api/ddnstasklist`，复制完整任务对象，再用 `PUT /api/ddns` 更新。`/api/ddns/manualSync/{param}`、Webhook 测试和命令测试会产生外部网络或命令执行副作用，不属于只读调用。

Lucky 3.0.0 的 Cloudflare DDNS 核心行为已经完成真实闭环验证。一次性 TEST 任务实际通过 `POST /api/ddns` 创建、回读、`PUT` 更新和 enable/disable；任务以 `V4QueryIPType=url` 从本机回环 HTTP 端点获取 IPv4，并使用记录值模板 `{ipv4Addr}` 将独立 Cloudflare TEST A 记录更新为查询结果。A 记录创建时 `SyncRecordData.ipv4Address` 不能为空；`{ipv4Addr}` 是已验证的动态替换模板，而 literal IP 会被当成固定目标值。随后将 TEST 记录值 PUT 为另一个文档保留地址并调用 `manualSync`，Cloudflare 记录再次真实更新；Webhook test 也实际向回环端点发出了 POST。完整可重复流程见 `tools/lucky_ddns_probe.py`，它会同时清理 Lucky TEST 任务与 Cloudflare TEST DNS 记录，并核对原 TaskKey 集合恢复。

## Web 服务、WAF 与认证

`webservice` 覆盖主规则、子规则、分组、发现、CGI、文件夹操作、轻面板、统计、WAF 事件和网页登录会话。`coraza` 管理 WAF 实例和规则集。

规则对象层级复杂，更新时必须保留未知字段。Web 重定向的状态码位于 `DefaultProxy.OtherParams.RedirectType`（子规则则在自身 `OtherParams`）；Lucky 3.0.0 已通过 API 验证 `"308"` 可用于 80 → HTTPS 永久跳转。更新已有监听器时先 GET 完整规则对象，再只修改目标字段并 PUT 回 `/api/webservice/rule/{RuleKey}`；不要用局部 JSON 覆盖复杂规则。统计导入、地理数据重建、IP 信息刷新和会话清理均会修改状态。文件服务与 CGI 还可能直接读写宿主机挂载目录。

普通 `reverseproxy` 的路径、Header 和重定向语义也已完成专项验证。`NginxConf` 并不是一个无语义的字符串：当前 3.0.0 前端与运行时均确认它支持 `proxy_set_header`、`proxy_hide_header`、`add_header`、`proxy_redirect`、`location` 和 Lucky 的 `path` 简写，可用于固定 Header 注入、响应头控制和路径级规则。`Domains` 带前端路径时，`location` / `path` 按移除该前缀后的请求路径匹配；`Locations` 自带的后端基础路径随后再与剩余路径拼接。`UseTargetHost`、自动反代重定向和专用协议/IP Header 开关的精确行为见 [WebService 反向代理语义](./webservice-reverse-proxy.md)。

Lucky 3.0.0 的 SNI 分流也已完成真实实例验证。子规则类型值为 `WebServiceType: "SNIRouting"`，`Domains` 保存要匹配的 SNI 域名，`Locations` 保存 `host:port` 形式的四层目标。父规则必须开启 TLS，但匹配到 SNI 子规则后 Lucky 会原样转发 TLS 流，而不是在 Lucky 上终止 TLS，因此后端本身仍需提供该域名的有效证书。`OtherParams.ProxyProtocolV2` 仅在后端明确支持 Proxy Protocol v2 时开启；当前 3.0.0 前端还提示单个 WebService 规则最多 6 条 SNI 分流。修改后应同时检查规则回读、SNI 日志和外部 TLS/业务请求。

## 端口转发与 STUN

- `portforward`：转发规则、启停、排序和模块配置；
- `stun` / `stunrule`：穿透规则、启停、排序、Webhook 与日志。

启用规则会立即改变网络暴露面。自动化保存后应验证监听地址、防火墙状态和目标服务，不要只检查 `ret: 0`。

NAT-PMP 映射已经通过 `tools/lucky_natpmp_ci_probe.py` 在 GitHub-hosted disposable Lucky 3.0.0 上完成真实协议与数据面闭环，而不是在 RS 生产公网网卡上制造 NAT。隔离拓扑由 Docker `--internal` Lucky LAN、独立 veth/network namespace synthetic WAN、owned STUN responder、NAT-PMP UDP/5351 gateway 和 UDP echo target 组成。Lucky 只通过 HTTP API 临时启用 STUN 模块并创建唯一 udp4 TEST rule，`NatPMP=true`、`UPnP=false`、`AutoOptionsFirewall=false`。CI 实际观察到 NAT-PMP UDP add，internal port 与 rule `ListenPort` 一致；fake gateway 分配 external UDP port 后创建 owned mapping relay，WAN namespace 的随机 marker 经 relay → Lucky → echo → Lucky → relay 完整原样返回。关闭/删除 rule 时又观察到 lifetime=0 delete，relay 随即消失，rule/module baseline 完整恢复。

UPnP mapping 也已通过 `tools/lucky_upnp_ci_probe.py` 独立完成，不是从 NAT-PMP 结果推断。probe 复用同类 isolated LAN/WAN 拓扑，但路由器侧改为只绑定 TEST bridge 的 stdlib IGD v1 fixture。Lucky 的 `UPnP=true` / `NatPMP=false` udp4 rule 实际发出 SSDP M-SEARCH，读取 fake IGD device description，然后调用 WANIPConnection 的 `GetExternalIPAddress` 与 `AddPortMapping`。AddPortMapping 实测为 UDP，internal client 等于 disposable Lucky IP，internal port 等于 `ListenPort`。fake IGD 为这条 owned mapping 建立 userspace relay 后，synthetic WAN 的随机 marker 能经 mapping → Lucky → echo target → Lucky → mapping 原样返回；关闭/删除 rule 后又收到 `DeletePortMapping` 并撤销 relay。当前成功运行中，另配的 TEST STUN Binding responder没有收到请求，说明 Lucky 3.0.0 这条 UPnP 路径可直接通过 IGD `GetExternalIPAddress` 得到公网端点；这只是当前运行时语义，不应外推成所有配置都绕过 STUN。

## 网络唤醒

`wol` 提供设备列表、服务配置、Webhook、客户端状态、唤醒和关机。`/api/wol/device/wakeup` 与 `/shutdown` 即使使用 GET 也有明显副作用，必须在调用方单独确认。

`tools/lucky_wol_ci_probe.py` 已在 GitHub-hosted 的 disposable Lucky 3.0.0 上验证真实 wake 数据面，但隔离目标不是一台真实机器：probe 创建唯一 Docker `--internal` bridge，Lucky admin 端口不 publish，临时 WOL device 使用 locally-administered 随机 MAC 与该 bridge 的私网 broadcast address；WOL Server 只在这个临时实例中由 API 从 disabled 切到 enabled。`GET /api/wol/device/wakeup?key=<TEST>` 返回 `ret=0` 后，raw capture **只绑定这张 internal bridge**，实际捕获到标准 102-byte magic packet（`ff`×6 + TEST MAC×16）。当前 Lucky 3.0.0 实测把 wake datagram 发往 **UDP/9**，即使 device 的 `Port` 字段设成另一个随机值也不会使用该值。结束后 device 被删除，Server/Client 恢复原 disabled 基线，临时容器/network 全部销毁；`shutdown` 从未调用。

这个闭环只证明 Lucky 确实发出了正确 WOL packet，不证明某台真实机器已经从离线变在线。synthetic TEST device 在 wake 前 `CanWakeup=true`、`State=Unknown`；在线状态变化必须留给明确可控的 powered test device，不应把 packet emission 当作 endpoint power-state 成功。

## 计划任务

`cron` 提供任务、分组、排序、表达式检查、日志和立即执行。`/api/cron/dojobs` 与 `/api/cron/jobs/trigger` 会执行任务；任务内部还可能调用脚本、Webhook、Docker 和其他 Lucky 模块。

## 证书、IP 数据与访问控制

- `ssl`：证书列表、刷新、下载、同步和凭据来源；
- `ipdb`：IP 数据库配置、下载、查询与实例；
- `ipfliter`：黑白名单、子规则、端口陷阱和自动记录；
- `security-groups`：安全组、授权主体和 OAuth 用户；
- `coraza`：WAF 规则和日志。

证书私钥、DNS API 凭据和用户授权信息不得出现在调试输出。下载证书前先确认接口是否包含私钥。Lucky 3.0.0 证书对象还支持 `MappingToPath`、`MappingPath`、`MappingChangeScript`：开启映射后会按证书 `Remark` 在目标目录生成 `<Remark>.key`、`<Remark>.pem` 等文件，并在证书更新后刷新。实测映射出的私钥默认权限可能为 `0644`，生产使用时应收紧到 `0600`，并可通过 `MappingChangeScript` 在后续续期后重新收紧权限/重载消费证书的服务。`GET /api/ssl/{key}` 的完整响应包含私钥材料，避免直接打印原始响应。

TEST ACME 生命周期也已完成真实闭环：独立证书对象经 POST 创建并真实签发，随后完成 PUT、启停、flush/manualsync 路径和删除；当 `MappingToPath` 在签发前已开启时，Lucky 实际生成 `<Remark>.key/.crt/.pem`。需要注意 Lucky 运行在 Docker 时路径属于 Lucky 自己的 mount namespace，不能把容器 `/tmp` 直接等同于宿主 `/tmp`。另外，已经存在证书 material 后才打开 mapping，并不会在当前 3.0.0 实测中立即回填旧 material。证书 sync-client 的 `linuxssh` 配置、Key 分配和 `AllSyncClient` 选择模型已经实践，但当前实例 `/api/info` 返回 `u=0`，`manualsync` 会在 SSH 传输前以 `PermissionDeniedCannotUseSyncFunction` 拒绝；这属于实例授权边界，不应通过客户端绕过。

IPDB 在 Lucky 3.0.0 上已经完成 `behavior-runtime` 闭环。`tools/lucky_ipdb_probe.py` 通过 Lucky 自己的 `POST /api/ipdb/upload` multipart 接口上传两份唯一 TEST GeoCN MMDB，创建并 PUT 更新 TEST item，随后通过 `GET /api/ipdb/item/{key}/true` 启用并等待 `Ready=true`。IPv4 与 IPv6 都实际通过 `/api/ipdb/query` 返回结果；`/api/ipdb/download?key=...` 下载得到的数据库与上传源文件 SHA-256 一致。probe 再把 item 切换到第二份上传文件并重新查询，最后删除 item 与两份数据库文件并验证原 item Key 基线恢复。注意 `/api/ipdb/item/{key}/{bool}` 虽然是 GET，但其真实语义是启用/禁用，属于写操作而不是只读接口。

## 存储与文件服务

- `storagemanagement`：本地与网盘挂载；
- `rclone`：远端、同步任务与第三方网盘授权；
- `ftpserver`、`webdav`、`smb`、`dlnaservice`、`third/filebrowser`：各类文件服务；
- `local-path-browser`：目录列举、创建和重命名。

这些接口可暴露或修改宿主机数据。路径参数应由服务端白名单约束，不能直接接受最终用户输入。网盘授权 URL、refresh token 和挂载配置都应脱敏。

StorageManagement 的 local storage 注册生命周期已在 Lucky 3.0.0 上完成隔离实践。`tools/lucky_storage_probe.py` 先通过 Lucky 自己的 `local-path-browser` 创建唯一 `/tmp/TEST-*` 目录，再验证当前前端的 GET list、POST / PUT / DELETE、`GET /api/storagemanagement/enable` 和 `litelist`。一个重要实测语义是：POST 请求即使显式带 `Enable=false`，新建 local item 首次回读仍会被 Lucky 规范化为 `Enable=true`；如需初始禁用，创建后必须再显式 disable。disabled item 会从 `litelist` 消失，重新 enable 后再次出现。

`Writable` 不再只是配置字段证据：`tools/lucky_webdav_probe.py` 使用两个 TEST storage 作为 localhost WebDAV 的 `store` mount，真实验证可写 mount 的 PUT / GET / DELETE 成功，而只读 mount 的 PUT 被拒绝且 backing path 没有生成目标文件。WebDAV probe 仅在原服务为 stopped 且 `Users` 为空时运行，临时绑定 `127.0.0.1` 高位端口、关闭 TLS 和 AutoFirewall，并在恢复前重新检查唯一 TEST 用户/端口 ownership marker，避免用旧快照覆盖并发配置。`SystemMount` 仍始终保持关闭，不能据此宣称系统挂载已经实践。

Rclone 的 local → local sync 也已完成文件级真实行为验证。`tools/lucky_rclone_sync_probe.py` 创建唯一源/目标 `/tmp/TEST-*` 目录和一个 sync task；一个短命、manual-only 的 TEST Cron helper 只在源目录写入随机 marker 文件。`CreateEmptyDirs=true` 的真实 `SyncMode=sync` run 以 `State.Status=success` 结束，同时把源侧空目录和真实文件复制到目标；run 后同一个 helper 被 PUT 改成内容比较脚本，只有源/目标 marker 内容一致时才会写出 owned verification marker，随后 helper task/group 立即删除。当前 Lucky 3.0.0 UI 只提供 `sync` / `bisync`，没有单独 `copy` mode，因此这里的 actual copy 是 sync 模式中的真实文件复制。随后同一 Rclone task 经 PUT 切换到 `DryRun=true`，新增第二个源目录与 post-sync marker 都没有出现在目标。compact `sync/list` 只返回路径、状态等摘要，完整的 `DryRun`、`CreateEmptyDirs`、过滤/性能选项应从 `GET /api/rclone/sync/{Key}` detail 读取。该闭环没有配置 remote、云盘凭据、bisync、schedule、network listener 或 system mount，结束后 Rclone 与 Cron task/group Key 基线、两个 TEST tree 都恢复。

`tools/lucky_rclone_stop_probe.py` 另外验证了真实 running task 的 stop。probe 只生成 **1 MiB** 本地 TEST 文件，并把任务设为 `Transfers=1`、`Checkers=1`、`BandwidthLimit=32K`，目的只是让 `State.Status=running` 稳定可观察；一旦进入 running 就立即 `POST /api/rclone/sync/stop/{Key}`。当前 Lucky 3.0.0 返回 `ret=0` 并退出 running，但随后 `State.Status` 被记为 **`success`**、`LastError` 为空，同时目标文件仍不存在。因此 Rclone 的这个 post-stop `success` 只能视为任务已进入终止态，不能据此断言同步完整成功。probe 完成后 task、Cron helper、1 MiB 文件和两个 TEST tree 全部清理并恢复 Key 基线。

SystemMount 也做过一次有界前置条件实践，但**当前部署不能宣称 mount/unmount 成功**。实践开始时 remote/sync baseline 都为空，因此先把原本为空的 Rclone global cache/upload path 临时改到唯一 `/tmp/TEST-*`，再创建 enabled local TEST remote，把 SystemMount 指向同一 TEST tree 内的独立 mount point。remote create 返回 `ret=0`，但 `MountMsg` 一直非空，mount point 没看到源目录；唯一带本次 TEST marker 的 Rclone 日志为 `unmountConflictFail: operation not permitted`。随后只读检查 Lucky 自身容器确认 `Privileged=false`、没有 `SYS_ADMIN`、也没有 `/dev/fuse` device mapping。remote disable/delete、global config 恢复为空和 TEST tree 删除均成功。不要为了把这个 checkbox 勾上而给生产 Lucky 容器提权；应在专用 privileged/FUSE 测试实例继续。

Cron 的 shell 子任务也已完成真实行为验证。`tools/lucky_cron_probe.py` 从空 task/group 基线创建唯一 TEST group 和两个 TEST task；当前前端/运行时确认一个 shell job 的最小结构为 `{Type:"shell_option", Options:{shell_content:<script>}, Remark:<label>}`。`Type=8` 的手动任务经 `GET /api/cron/dojobs` 实际在 Lucky 自己的 `/tmp/TEST-*` 写入 marker；同一任务经 PUT 改为 `Type=4`、`TypeParams="2"` 后，在不手动触发的情况下由调度器自动写入第二个 marker。另一个 `exit 7` 子任务经 `POST /api/cron/jobs/trigger` 单独触发后，Cron 日志出现对应失败记录。整个闭环不访问网络、不切换业务服务，最后删除 TEST task/group/path 并恢复原 Key 基线。

FTP 现已通过 `tools/lucky_ftp_ci_probe.py` 在 GitHub-hosted 的一次性 Lucky 3.0.0 容器中完成真实数据面闭环，RS 生产实例仍保持不启动 FTP。原因没有改变：FTP 配置只有 `Network + Port + PassivePortStart/End`，没有 WebDAV 那样的 `ListenIP`。CI probe 因此把 Lucky admin、FTP control 以及整段 PASV 端口都通过 Docker **只发布到 runner 的 `127.0.0.1`**，同时设置 `AutoFireWall=false`、`DisableActiveMode=true`，所有 Lucky 配置写入仍只走 HTTP API，不修改宿主防火墙。

最终闭环使用一个随机 TEST 用户和一个 local `MountList`，先确认错误密码被拒绝，再用 Python 标准库 FTP 客户端完成 passive login、根目录 LIST/NLST、`STOR` 上传、`RETR` 下载和 `DELE` 删除，并从 runner backing directory 逐字节交叉验证文件内容。实测还补出两个重要语义：Lucky 3.0.0 要求 `PassivePortEnd - PassivePortStart >= 9`，所以 probe 使用连续 10 个 PASV 端口；当用户只有一个 local mount 时，该 mount **直接就是 FTP 根目录**，`DisplayName` 不会再生成一层虚拟目录。结束后 probe 通过 ownership check PUT 回原始 stopped/empty 配置，再删除整个临时 Lucky 容器与 TEST 目录。

SMB 已通过 `tools/lucky_smb_probe.py` 完成真正的 loopback SMB2 文件闭环，而且不依赖 `smbclient` 或第三方 Python SMB 库。probe 只在原 SMB 为 stopped、`Users/PublicMountList` 为空时运行，创建唯一 `/tmp/TEST-*` local root，并以 `ListenIP=127.0.0.1`、`ListenNetwork=tcp4`、随机高位端口启动一个 guest public share；`AutoFirewall=false`，WSDD/mDNS/NBNS 全部关闭。公共 share 的编辑模型为 `Type / Param / DisplayName / Writable / DisableChangeWriteTable`，其中 `DisplayName` 已真实作为 TREE_CONNECT 的 SMB share name 使用。

最终客户端是纯 Python 标准库实现的 SMB2 client：`NEGOTIATE` 只提供 SMB 2.0.2/2.1，当前 LiteSMB 选择 `0x0210`；在 `GuestEnable=true` 的隔离配置下，raw NTLMSSP Type 1 直接建立 guest session，响应 `SessionFlags=1`。随后 TREE_CONNECT、CREATE(delete-on-close)、WRITE、READ、CLOSE、TREE_DISCONNECT 和 LOGOFF 全部成功，读回内容与内存 marker 完全一致；Lucky local-path-browser 在文件打开期间能看到 backing file，CLOSE 后文件消失。宿主 curl 虽声明支持 `smb/smbs`，但实测发送 SMB1，被 LiteSMB 明确以 `client does not support SMB2` 拒绝，因此仓库不为此安装额外 SMB 客户端。恢复前会核对 loopback listener 与唯一 share ownership marker，最终原 stopped 配置和 TEST tree 全部恢复。

DLNA 已通过 `tools/lucky_dlna_probe.py` 完成隔离 HTTP/UPnP 行为闭环，但隔离方式不是 loopback。首次尝试只选择 `lo` 时，Lucky 日志明确返回 `interface 'lo' is not appropriately configured (it should be UP, MULTICAST and MTU > 0)`；probe 因此拒绝修改宿主网卡，转而只允许选择名称为 `br-*`、状态 `UP+MULTICAST`、仅有私网 IPv4、且 `ip link show master <bridge>` 没有任何 veth attachment 的空 Docker bridge。服务只绑定该 bridge 的随机高位 HTTP 端口，`NetInterfaceList` 也只包含同一 bridge，不触碰物理网卡、Tailscale/WireGuard 或已有业务容器。

在这个 host-local 私网隔离环境中，DLNA `PUT /api/dlnaservice/configure` 返回 `ret=0` 并启动成功；`GET /rootDesc.xml` 返回 `text/xml` 的 UPnP device description，声明 `ContentDirectory` 服务。probe 对其 control URL 发送标准 SOAP `Browse(ObjectID=0, BrowseDirectChildren)`，收到 HTTP 200，并在返回结果中看到唯一 TEST media root 下的 `album` 子目录，证明本地 mount 不只是配置回读而是真的进入 ContentDirectory。当前 rootDesc 的 `friendlyName` 没有跟随 TEST `FriendlyName` 配置值，仓库把它作为运行时语义记录，不宣称该字段能覆盖设备描述。宿主从同一空 bridge 发出的 SSDP M-SEARCH 在当前内核/bridge 条件下仍为 0 回包，因此只宣称 HTTP/UPnP SOAP 行为成功，不宣称 host-side SSDP discovery 成功。恢复前再次核对 TEST FriendlyName、listener、interface 和 mount ownership marker；最终原 stopped 配置和 TEST tree 全部恢复。

FileBrowser 已通过 `tools/lucky_filebrowser_probe.py` 完成独立 loopback 行为闭环。probe 只在原 FileBrowser 为 stopped/disabled 时运行，创建唯一 `/tmp/TEST-*` root、cache 和全新 TEST DB，以 `127.0.0.1` + `tcp4` + 随机高位 HTTP 端口启动服务，同时关闭 TLS、AutoFirewall 和 exec。local mount 的编辑模型为 `Type / Param / DisplayName / Writable / DisableChangeWriteTable`，运行时回读还确认 `InvalidMsg / IsLocalDir`；当 `MountList` 只有一个 local mount 时，FileBrowser 的 `/api/resources/` 直接就是该目录内容，而不是再生成一层虚拟 mount 目录。

全新 TEST DB 可直接用 FileBrowser 文档化的 reset-default `666/666` 登录，probe **不会**调用 Lucky 的高风险 `resetadmin`；登录得到的 JWT 只保存在进程内并作为 `X-Auth` 使用。实际文件闭环已经验证：raw POST upload 返回 200、资源 GET 返回 200 并读回相同 TEST 内容、PATCH rename 返回 200，DELETE 正常成功码为 **204**，对应 Lucky-visible backing file 同步创建、改名并消失。恢复前 probe 会重新确认 DB path、listener port 和 mount Param 仍是本次 TEST ownership marker，只有匹配时才 PUT 回原配置；最终 stopped 状态、完整配置和 TEST path 均恢复基线。

## Docker

`docker` 是最大的接口族之一，覆盖：

- 容器创建、启停、重启、删除、改名、复制、升级、编辑、日志、统计、进程和文件；
- 镜像拉取、导入、导出、构建、推送、升级检查和批量升级；
- 网络、卷、标签、仓库镜像源与清理；
- Compose 发现、读取、备份、恢复、启动、停止和异步任务。

OpenToken 能调用这些端点时，实际权限接近 Docker daemon 权限，通常等价于宿主机 root。生产自动化应使用独立代理层只暴露允许的操作，而不是把 OpenToken 直接交给业务代码。

Docker Compose 的核心生命周期已通过 `tools/lucky_docker_compose_probe.py` 完成隔离行为验证。probe 复用一个已经存在的镜像，不执行 pull/build；两个唯一 TEST project 都放在 Lucky 可见的 `/tmp/TEST-*` 下，容器使用 `network_mode: none`，不发布端口、不声明 volume。一个 fresh project 验证 synchronous `up → down`；另一个按当前 Lucky 3.0.0 UI 的真实流程验证 `up-async → compose_up task success → projects/ps/config/logs → stop-async → compose_stop task success → start → restart → down-async → compose_down task success`。实测还确认 synchronous `up` 不是对已存在 project 的幂等 re-up：同名 project 会返回名称已存在错误。

Docker async task 的清理语义需要特别区分：`DELETE /api/docker/tasks/{id}` 是 active-task cancel，completed task 会被拒绝；completed history 由 `DELETE /api/docker/tasks` 清理。因此 runtime probe 只有在 task baseline 原本为 0、且当前 task ID 集合与本次 probe 获得的 ID **完全相等**时才允许全局 clear。probe 结束后 project/container/task/image/network/volume identity 基线全部恢复，两个 TEST path 均删除。生产环境仍禁止为了覆盖率执行真实 Docker prune。

Docker image 的 import/save/load 也已通过 `tools/lucky_docker_image_import_probe.py` 完成隔离验证，且没有执行 pull 或 build。probe 先用 owned Cron task 在 Lucky 自己的 `/tmp/TEST-*` 生成只含一个文本文件的 raw rootfs tar，`POST /api/docker/images/import` 实际只创建一个 disposable image；随后为它添加唯一 TEST tag，`save.withoutcompression` 返回真实 `application/x-tar`，删除 image 后再通过 `/api/docker/images/load` 恢复相同 image identity 与 TEST tag。当前 UI 的导入流程还会先 multipart POST `/api/docker/images/upload-temp`，再把返回 path 交给 load；这条 direct Axios route 已纳入静态 extractor。当前 RS 实例对真实 multipart 请求返回 `Temp operation path not configured`，与 UI 自身的 preflight 检查一致，因此没有为了覆盖率修改生产全局 Docker `temp_operation_path`。

三个 image build 入口现也已完成隔离行为验证，但 **ZIP/Git build 从未在 RS 生产 Docker daemon 上执行**。`/api/docker/images/build` 的实际请求语义是 `{dockerfile:<Dockerfile 文本>}`，早期 disposable probe 已真实构建成功；`tools/lucky_docker_build_ci_probe.py` 则硬性拒绝非 GitHub Actions 环境，启动精确 pin 到已验证 digest 的 fresh Lucky 3.0.0，只把后台端口发布到 runner `127.0.0.1`，并连接 GitHub-hosted runner 的临时 Docker daemon。ZIP handler 使用只含 Dockerfile + marker 的 `FROM scratch` context；Git handler 把一个只支持 `clone` 的 fake git wrapper 挂入临时 Lucky，将只读 owned fixture 复制到 Lucky 指定 clone 目录，因此完整走过 Lucky 的 clone→build handler，但不访问外部 Git 服务。两条成功响应都精确为 `ret + output`，且 `output` 为 string；生成镜像通过唯一 label 和 `/marker.txt` 内容双重校验，最后临时 Lucky 和所有 post-baseline image ID 全部删除、image baseline 精确恢复。

## Web 终端

`webterminal` 提供本地 Shell、SSH/Telnet 连接、会话、SFTP、分屏与快捷指令。连接和附加接口使用 WebSocket。该模块可执行命令与传输文件，是最高风险区域之一。

Lucky 3.0.0 已完成两条隔离行为验证。local connection 通过 temporary-access ticket 建立真实 WebSocket；服务端先发送 `connecting/connected` JSON 事件并给出 `sessionId`，普通终端输入输出使用原始 text/binary frame，resize 使用 `{type:"resize",cols,rows}`。仅关闭 WebSocket 会让 session 进入 `detached`，随后可经 attach 路径恢复同一 session；显式 DELETE 才关闭 session。

localhost SSH 还验证了首次 host-key 流程：connection test 返回 `ret=409 SSHHostKeyUntrusted` 和 host-key 元数据，经专用 PUT 保存信任后，重新提供测试私钥的第二次 test 返回 `ret=0`。同一 SSH session 的 SFTP 已验证 list/mkdir/touch/write/read/rename/copy/chmod/remove，以及基于目标机现有 `tar+gzip` 的 compress/preview/decompress。当前 3.0.0 有两个可重复缺陷：multipart `/upload` 即使按前端 `file → path → filename` FormData 顺序构造仍返回 `ret=5 SSH_FX_FAILURE`；`/upload-streaming` 则出现 `ret=4 closed pipe` / `BrokenPipe`。不要把这两个路由标成已支持成功行为。

## Cloudflared 与 FRP

`cloudflared` 和 `frp` 管理隧道实例、排序与日志。改变路由或隧道配置会直接改变公网可达性。更新后应从内外网分别验证 DNS、TLS 和回源行为。

FRP 的普通 TCP proxy 和 STCP visitor 都已完成纯 loopback 行为验证。`tools/lucky_frp_probe.py` 在同一 Lucky 里启动 disposable `frps + frpc`，用一个只监听 `127.0.0.1` 的 echo origin 验证 TCP proxy 的真实双向字节往返；`tools/lucky_frp_visitor_probe.py` 则进一步使用一个 loopback frps、一个 provider frpc 和一个独立 visitor frpc。provider 创建 `type=stcp` 的 TEST proxy，visitor 创建对应 `type=stcp` visitor 并只绑定 `127.0.0.1:<随机端口>`，真实 payload 经 `visitor frpc → frps → provider frpc → echo` 原样返回。

Visitor 的当前前端默认模型为 `type=stcp`、`bindAddr=127.0.0.1`、`bindPort=0`，另含 `serverName / secretKey / serverUser / transport / protocol / keepTunnelOpen / retry / fallback / natTraversal / plugin`。运行时 probe 使用内存生成的独立 FRP auth token 和 STCP secret，不输出任何 secret；第一次 roundtrip 成功后，又通过 `PUT /api/frp/{client}/visitors` 把 `transport.useEncryption/useCompression` 同时打开，GET readback 两个布尔值为 true，第二个不同 payload 仍成功往返。一个需要保留的语义是：当前 STCP visitor 明明能实际传输数据时，`GET /api/frp/{client}/status` 仍可能返回空的 `visitorStatuses`，因此 data-plane roundtrip 比 status collection 更强。最终 visitor/proxy 和三个 TEST FRP instance 都显式清理，instance-key 基线恢复。

## 第三方登录与 OAuth

`thirdPartyAuthManager`、`oauth`、`security-groups` 和 `webservice/webauth` 共同管理第三方身份、授权用户和会话。不要记录临时 code、回调参数、用户标识或会话票据。

当前前端把“添加第三方用户”的授权过程拆成 `GET /api/oauth/tmpcode?type=<provider>` → 打开返回的 `authUrl` → 轮询 `/api/oauth/status` → `/api/oauth/userinfo`；管理员 OAuth 登录则另走 `/api/login/challenge`，对 `{type,token,twoFA,challengeId,nonce}` 做 RSA 分块加密后 `POST /api/oauth/login`。这两条链不能混用 callback code、tmpCode 或用户 Key。

OIDC 已通过 `tools/lucky_oauth_ci_probe.py` 完成真实隔离 E2E。GitHub Actions 中启动 pinned Lucky 3.0.0、owned stdlib OIDC Provider，并通过 Lucky API 创建一个 WebService `oauth` 规则作为 Lucky 官方架构里的中间认证接口。管理授权链真实完成 `tmpCode/authUrl → authorize → Lucky relay callback → token → userinfo → status(auth=true) → /api/oauth/userinfo`，随后把 TEST 身份保存为第三方用户，验证 disable/re-enable、二次授权更新，并把该用户 Key 明确加入 `ThirdAuthLoginUserList`。登录链再申请一个 fresh tmpCode，等 `status.auth=true` 后复刻前端 `/api/login/challenge` + RSA 分块加密并调用 `/api/oauth/login`，最终得到 `ret=0` 和非空 Lucky login token。Lucky 前端统一追加的 `_` anti-replay 时间戳/校验 query 对这个登录闭环是实际需要复刻的语义。最后 revoke 用户、删除 relay、恢复 OIDC 配置与用户基线。OpenToken-only `tmpcode(type=oidc)` 在生产式上下文仍会 `ret=2`，所以不能把 OpenToken-only 能力与完整交互授权混为一谈。

Security Group + WebService Auth 的核心链路已通过 `tools/lucky_security_group_probe.py` 完成隔离 E2E。probe 创建唯一 TEST group、组内 local user、无 group local user，以及不携带真实 provider token 的 disabled third-party/OAuth mapping；随后只向现有 WebService 父规则 append 两条 TEST 子规则。BasicAuth 对未认证/错误密码返回 401，正确组内 local user 能到达 loopback marker origin。WebAuth 则实际恢复并执行了 challenge + RSA 登录协议：先取 `challengeId/nonce/publicKey`，再对 `{account,password,twoFA,challengeId,nonce}` 做分块 RSA 加密并提交，成功 session 能到达 upstream，而无 group 用户不能获得同等访问。

成功 WebAuth 授权会生成 runtime Security Group grant；当前运行时/前端确认真实主键字段为 `GrantKey`。早期 probe 在显式删除时曾错误使用通用 `Key`，修正为 `GrantKey` 后没有为了覆盖率再重复整套生产 listener E2E，所以仓库只宣称 grant **生成**以及最终 principal cleanup 后 grant baseline 恢复，不宣称修正后的显式 grant-delete 已再次验证。对于 `AuthSource=securityGroup` 的 BasicAuth/WebAuth，当前前端会把 `SecurityGroupAccessMode` 置为 `disabled`；`strict/append` 是另一套授权叠加模式，不应混为一谈。清理后所有 TEST principals/subrules 消失，原 WebService 业务子规则对象级保持不变。

## 其他模块

`iconlib`、`frontend-preferences`、`about-content`、`natdetect`、`describeviewtree` 等用于界面偏好、图标源、说明内容、NAT 检测和诊断视图。即使看似只影响前端，也应先确认是否会从外部 URL 下载内容或写入配置。
