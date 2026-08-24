# Evidence

`lucky-v3-endpoints.json` 是从获授权本机 Lucky v3 前端 bundle 派生的端点元数据，不包含 bundle 内容、OpenToken、安全入口、主机名或 API 原始响应。

字段说明：

- `target`：分析目标版本；
- `bundle_sha256`：用于判断前端是否变化；
- `path` / `method`：归一化路径与推断方法；
- `query_keys` / `body_keys`：能够从字面量恢复的字段，不保证完整；
- `evidence`：提供调用证据的 bundle 文件名；
- `confidence`：`frontend-call` 或 `route-literal-only`。

该文件由 [extract_lucky_frontend.py](../tools/extract_lucky_frontend.py) 生成。

`lucky-v3-runtime-verification.json` 另外记录获授权 Lucky 3.0.0 实例上的脱敏运行时证据。除路由/风险/schema 外，`model_evidence` 可记录无法仅从单个 API 路由表达的跨模块对象语义，例如 WebService `SNIRouting` 子规则与 SSL 证书映射行为。此类条目只能保存通用字段、类型和验证结论；真实域名、RuleKey、IP/端口、证书/私钥及凭据不得持久化到仓库。
