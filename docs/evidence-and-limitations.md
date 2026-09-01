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
| StorageManagement | 已验证 local storage POST/PUT/DELETE、启停与 litelist 联动；创建会强制变为 enabled，Writable 已通过 WebDAV consumer 做真实读写验证，SystemMount 尚未实践 |
| WebDAV | 已验证 127.0.0.1 临时服务、TEST 用户、OPTIONS/PROPFIND、store mount 可写/只读权限、日志与完整配置恢复 |
| Rclone | 已验证 local → local sync 实际运行与 DryRun 对照，task detail / State / logs / 清理闭环 |
| Cron | 已验证 `shell_option`、整任务手动 trigger、单 job trigger、每 2 秒真实调度、失败日志与 task/group/path 清理闭环 |
| Docker Compose | 已验证 isolated fresh sync up/down、current-UI async up/stop/down task、ps/config/logs、start/restart、task-history ownership gate 与六类资源基线恢复 |
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

- merged catalog 中共有 **242 条 POST / PUT / PATCH**；
- **218 条**带请求体并生成 OpenAPI `requestBody`；
- 这 218 条中仅剩 **1 条**仍含未类型化顶层属性；
- 显式 response schema 已覆盖 **338 条**路由；
- response 侧未定型 `{}` 叶子已降到 **0**；request 侧仍有 **38** 个。

目前重点覆盖 DDNS、WebService、Docker、FRP、SSL/ACME、Security Groups、IPFilter/PortTrap、PortForward、STUN、WebTerminal、StorageManagement、WebDAV、Rclone、Cron，以及部分 WOL、FileBrowser、Status、IPDB、Modules 等接口。DDNS 的 Cloudflare 核心链路已提升到 `behavior-runtime`：独立 TEST 任务完成 CRUD、URL 取 IPv4、真实 DNS A 更新、manualSync、Webhook test 与双边清理；provider 密钥和真实业务记录未写入证据。IPDB 也已完成隔离 MMDB 的上传、item CRUD、启停、IPv4/IPv6 查询、下载哈希校验、数据库文件切换和清理闭环；其中 `GET /api/ipdb/item/{key}/{bool}` 已确认具有写副作用。WebTerminal 已完成真实 ticketed WebSocket、raw shell I/O、resize、session detach/attach、localhost SSH host-key 信任与 SFTP mkdir/touch/write/read/rename/copy/chmod/remove、tar.gz compress/preview/decompress；multipart upload 在匹配当前前端 FormData 形状后仍返回 `SSH_FX_FAILURE`，streaming upload 则稳定复现 `closed pipe` / `BrokenPipe`，两项按 Lucky 3.0.0 运行时缺陷记录。StorageManagement 的 local item 已完成创建、PUT、启停、litelist 联动、日志读取与删除，并确认创建时 `Enable=false` 会被规范化为 enabled；其 `Writable` 现已通过 loopback WebDAV 的真实 PUT/GET/DELETE 与只读写拒绝验证。Rclone 已完成 local → local sync 的真实运行与 DryRun 对照；Cron 也已完成 shell job 的整任务手动触发、单 job 触发、每 2 秒真实调度与失败日志闭环。Docker Compose 现已完成 fresh synchronous up/down 与 current-UI async up/stop/down task 生命周期，并验证 ps/config/logs、start/restart、`network_mode=none`、零端口/零 volume、completed-task 清理语义及 project/container/task/image/network/volume 六类 identity baseline 恢复；真实 Docker prune 仍保持禁止。`SystemMount`、FTP 公网监听场景以及其他文件服务仍保持未验证/隔离待办。

## 已知限制

- 前端未调用的后端接口可能无法发现。
- 动态路径只能归一化为 `{param}`，真实参数语义可能未知。
- 静态分析不能可靠推导所有必填字段、错误码、事务语义或 WebSocket 消息格式。
- 路由存在不代表写请求一定安全，也不代表请求体 schema 已完全验证。
- 不同模块、镜像和 Lucky 后续版本可能改变接口集合和行为。
- WebSocket 已在 NAT Detect 与 WebTerminal 上完成真实会话验证，但并非所有 WebSocket 路由都已恢复消息协议；当前 stdlib helper 已支持 HTTP 101 后同一 TCP read 内紧跟首个 WebSocket frame 的合法情况。
- SSL sync-client 的配置、选择模型和授权拒绝已实测；当前实例 `/api/info` 为 `u=0`，`manualsync` 在真正 linuxssh 文件传输前返回 `PermissionDeniedCannotUseSyncFunction`，因此不能宣称 sync-client E2E 文件传输已完成。
- FTP 当前配置没有 loopback `ListenIP` 字段，行为测试不会为了覆盖率在生产宿主临时开放控制/PASV 监听；应在隔离 network namespace 或专用测试环境继续。

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
