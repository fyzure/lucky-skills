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
| 308 重定向 | 已验证 `RedirectType="308"`，GET / POST 均返回 308 |
| WebService SNI 分流 | 已验证 `WebServiceType="SNIRouting"`、`Domains` + `Locations`，公网 TLS 流量经 SNI 路由进入本地 TLS 服务 |
| SSL 证书映射 | 已验证 `MappingToPath` / `MappingPath` / `MappingChangeScript`，并确认映射文件随证书对象生成 |
| `UNKNOWN` 路由 | 当前默认合并目录为 0 |
| OpenToken 鉴权 | 安全入口 + `openToken` 请求头 |
| 状态接口限流 | 当前实例约 20 请求/秒 |

真实 OpenToken、安全入口、域名和业务配置不会写入仓库。

SNI/证书映射验证同样只保留通用字段语义和脱敏后的行为结论，不保存真实域名、规则 Key、后端地址、证书正文、私钥或 ACME 凭据。SNI 流量验证包含真实外部 TLS/HTTP CONNECT 与 Git smart-HTTP 只读操作，以确认四层双向转发，而不是只依据 Lucky 的 `ret: 0`。

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
- 显式 response schema 已覆盖 **324 条**路由；
- response 侧未定型 `{}` 叶子已降到 **0**；request 侧仍有 **38** 个。

目前重点覆盖 DDNS、WebService、Docker、FRP、SSL/ACME、Security Groups、IPFilter/PortTrap、PortForward、STUN，以及部分 Rclone、Cron、WOL、Storage、FileBrowser、Status、IPDB、Modules 等接口。

## 已知限制

- 前端未调用的后端接口可能无法发现。
- 动态路径只能归一化为 `{param}`，真实参数语义可能未知。
- 静态分析不能可靠推导所有必填字段、错误码、事务语义或 WebSocket 消息格式。
- 路由存在不代表写请求一定安全，也不代表请求体 schema 已完全验证。
- 不同模块、镜像和 Lucky 后续版本可能改变接口集合和行为。
- 当前客户端不会建立 WebSocket 会话，只验证相关路由或鉴权层。

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
