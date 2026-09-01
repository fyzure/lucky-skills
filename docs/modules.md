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

## 网络唤醒

`wol` 提供设备列表、服务配置、Webhook、客户端状态、唤醒和关机。`/api/wol/device/wakeup` 与 `/shutdown` 即使使用 GET 也有明显副作用，必须在调用方单独确认。

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

Rclone 的 local → local sync 也已完成真实行为验证。`tools/lucky_rclone_sync_probe.py` 创建唯一源/目标 `/tmp/TEST-*` 目录和一个 sync task；`CreateEmptyDirs=true` 的真实 run 把源侧空目录传播到目标侧并以 `State.Status=success` 结束。随后同一 task 经 PUT 切换到 `DryRun=true`，新增第二个源目录再次运行成功，但目标侧没有生成对应目录。compact `sync/list` 只返回路径、状态等摘要，完整的 `DryRun`、`CreateEmptyDirs`、过滤/性能选项应从 `GET /api/rclone/sync/{Key}` detail 读取。该闭环没有配置 remote、云盘凭据、bisync、schedule、network listener 或 system mount。

Cron 的 shell 子任务也已完成真实行为验证。`tools/lucky_cron_probe.py` 从空 task/group 基线创建唯一 TEST group 和两个 TEST task；当前前端/运行时确认一个 shell job 的最小结构为 `{Type:"shell_option", Options:{shell_content:<script>}, Remark:<label>}`。`Type=8` 的手动任务经 `GET /api/cron/dojobs` 实际在 Lucky 自己的 `/tmp/TEST-*` 写入 marker；同一任务经 PUT 改为 `Type=4`、`TypeParams="2"` 后，在不手动触发的情况下由调度器自动写入第二个 marker。另一个 `exit 7` 子任务经 `POST /api/cron/jobs/trigger` 单独触发后，Cron 日志出现对应失败记录。整个闭环不访问网络、不切换业务服务，最后删除 TEST task/group/path 并恢复原 Key 基线。

FTP 当前仍保持未启动。Lucky 3.0.0 的 FTP 配置只有 `Network + Port + PassivePortStart/End`，没有 WebDAV 那样的 `ListenIP`；为了行为覆盖而临时启动会使随机控制/PASV 端口监听所选 network 的全部地址。因此当前实例不为测试启动 FTP，也不修改宿主防火墙来人为制造隔离；真实 FTP 登录/传输应放在 network namespace 或专用隔离环境中完成。

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

Docker image 的 import/save/load 也已通过 `tools/lucky_docker_image_import_probe.py` 完成隔离验证，且没有执行 pull 或 build。probe 先用 owned Cron task 在 Lucky 自己的 `/tmp/TEST-*` 生成只含一个文本文件的 raw rootfs tar，`POST /api/docker/images/import` 实际只创建一个 disposable image；随后为它添加唯一 TEST tag，`save.withoutcompression` 返回真实 `application/x-tar`，删除 image 后再通过 `/api/docker/images/load` 恢复相同 image identity 与 TEST tag。当前 UI 的导入流程还会先 multipart POST `/api/docker/images/upload-temp`，再把返回 path 交给 load；这条 direct Axios route 已纳入静态 extractor。当前实例对真实 multipart 请求返回 `Temp operation path not configured`，与 UI 自身的 preflight 检查一致，因此没有为了覆盖率修改全局 Docker `temp_operation_path`。本地 context build、ZIP/Git build 仍不得在 RS 生产 Docker daemon 上执行，应放到 temporary Lucky + mock Docker 或 GitHub Actions 隔离环境。

## Web 终端

`webterminal` 提供本地 Shell、SSH/Telnet 连接、会话、SFTP、分屏与快捷指令。连接和附加接口使用 WebSocket。该模块可执行命令与传输文件，是最高风险区域之一。

Lucky 3.0.0 已完成两条隔离行为验证。local connection 通过 temporary-access ticket 建立真实 WebSocket；服务端先发送 `connecting/connected` JSON 事件并给出 `sessionId`，普通终端输入输出使用原始 text/binary frame，resize 使用 `{type:"resize",cols,rows}`。仅关闭 WebSocket 会让 session 进入 `detached`，随后可经 attach 路径恢复同一 session；显式 DELETE 才关闭 session。

localhost SSH 还验证了首次 host-key 流程：connection test 返回 `ret=409 SSHHostKeyUntrusted` 和 host-key 元数据，经专用 PUT 保存信任后，重新提供测试私钥的第二次 test 返回 `ret=0`。同一 SSH session 的 SFTP 已验证 list/mkdir/touch/write/read/rename/copy/chmod/remove，以及基于目标机现有 `tar+gzip` 的 compress/preview/decompress。当前 3.0.0 有两个可重复缺陷：multipart `/upload` 即使按前端 `file → path → filename` FormData 顺序构造仍返回 `ret=5 SSH_FX_FAILURE`；`/upload-streaming` 则出现 `ret=4 closed pipe` / `BrokenPipe`。不要把这两个路由标成已支持成功行为。

## Cloudflared 与 FRP

`cloudflared` 和 `frp` 管理隧道实例、排序与日志。改变路由或隧道配置会直接改变公网可达性。更新后应从内外网分别验证 DNS、TLS 和回源行为。

## 第三方登录与 OAuth

`thirdPartyAuthManager`、`oauth`、`security-groups` 和 `webservice/webauth` 共同管理第三方身份、授权用户和会话。不要记录临时 code、回调参数、用户标识或会话票据。

Security Group + WebService Auth 的核心链路已通过 `tools/lucky_security_group_probe.py` 完成隔离 E2E。probe 创建唯一 TEST group、组内 local user、无 group local user，以及不携带真实 provider token 的 disabled third-party/OAuth mapping；随后只向现有 WebService 父规则 append 两条 TEST 子规则。BasicAuth 对未认证/错误密码返回 401，正确组内 local user 能到达 loopback marker origin。WebAuth 则实际恢复并执行了 challenge + RSA 登录协议：先取 `challengeId/nonce/publicKey`，再对 `{account,password,twoFA,challengeId,nonce}` 做分块 RSA 加密并提交，成功 session 能到达 upstream，而无 group 用户不能获得同等访问。

成功 WebAuth 授权会生成 runtime Security Group grant；当前运行时/前端确认真实主键字段为 `GrantKey`。早期 probe 在显式删除时曾错误使用通用 `Key`，修正为 `GrantKey` 后没有为了覆盖率再重复整套生产 listener E2E，所以仓库只宣称 grant **生成**以及最终 principal cleanup 后 grant baseline 恢复，不宣称修正后的显式 grant-delete 已再次验证。对于 `AuthSource=securityGroup` 的 BasicAuth/WebAuth，当前前端会把 `SecurityGroupAccessMode` 置为 `disabled`；`strict/append` 是另一套授权叠加模式，不应混为一谈。清理后所有 TEST principals/subrules 消失，原 WebService 业务子规则对象级保持不变。

## 其他模块

`iconlib`、`frontend-preferences`、`about-content`、`natdetect`、`describeviewtree` 等用于界面偏好、图标源、说明内容、NAT 检测和诊断视图。即使看似只影响前端，也应先确认是否会从外部 URL 下载内容或写入配置。
