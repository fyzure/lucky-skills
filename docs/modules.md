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

## 存储与文件服务

- `storagemanagement`：本地与网盘挂载；
- `rclone`：远端、同步任务与第三方网盘授权；
- `ftpserver`、`webdav`、`smb`、`dlnaservice`、`third/filebrowser`：各类文件服务；
- `local-path-browser`：目录列举、创建和重命名。

这些接口可暴露或修改宿主机数据。路径参数应由服务端白名单约束，不能直接接受最终用户输入。网盘授权 URL、refresh token 和挂载配置都应脱敏。

## Docker

`docker` 是最大的接口族之一，覆盖：

- 容器创建、启停、重启、删除、改名、复制、升级、编辑、日志、统计、进程和文件；
- 镜像拉取、导入、导出、构建、推送、升级检查和批量升级；
- 网络、卷、标签、仓库镜像源与清理；
- Compose 发现、读取、备份、恢复、启动、停止和异步任务。

OpenToken 能调用这些端点时，实际权限接近 Docker daemon 权限，通常等价于宿主机 root。生产自动化应使用独立代理层只暴露允许的操作，而不是把 OpenToken 直接交给业务代码。

## Web 终端

`webterminal` 提供本地 Shell、SSH/Telnet 连接、会话、SFTP、分屏与快捷指令。连接和附加接口使用 WebSocket。该模块可执行命令与传输文件，是最高风险区域之一。

## Cloudflared 与 FRP

`cloudflared` 和 `frp` 管理隧道实例、排序与日志。改变路由或隧道配置会直接改变公网可达性。更新后应从内外网分别验证 DNS、TLS 和回源行为。

## 第三方登录与 OAuth

`thirdPartyAuthManager`、`oauth`、`security-groups` 和 `webservice/webauth` 共同管理第三方身份、授权用户和会话。不要记录临时 code、回调参数、用户标识或会话票据。

## 其他模块

`iconlib`、`frontend-preferences`、`about-content`、`natdetect`、`describeviewtree` 等用于界面偏好、图标源、说明内容、NAT 检测和诊断视图。即使看似只影响前端，也应先确认是否会从外部 URL 下载内容或写入配置。
