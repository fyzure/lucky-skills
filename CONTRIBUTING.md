# Contributing

## 原则

- 只对你拥有或获授权的 Lucky 实例采集证据。
- 默认只执行明确无副作用的 GET；不要携带 OpenToken 批量试探未知路由或未知方法。
- 不提交前端 bundle、原始配置、原始响应或访问日志。
- 示例只能使用占位符和环境变量。
- 新结论应标注为 `runtime-verified`、当前前端推断或历史源码，并区分“方法/路由存在”与“业务行为已执行验证”。

## 更新流程

1. 将目标版本页面引用的 JavaScript bundle 放在仓库外的临时目录。
2. 运行 `tools/extract_lucky_frontend.py` 更新证据 JSON。
3. 审核 `evidence/lucky-v3-runtime-verification.json`：只保留脱敏后的方法、查询键、风险覆盖、schema 元数据、验证说明和已确认的字面量误报；运行时证据必须同时绑定 Lucky 版本和静态快照 SHA-256，只要静态快照变化就必须重新审核/核验，不得沿用旧绑定。仅证明 `METHOD + path` 存在的 GitHub-hosted 无鉴权校准结果放入独立 `route_method_ci_evidence`，不得冒充成功 handler 行为；其 missing-route 404 对照、鉴权返回、隔离网络与未启用 OpenToken 条件必须保留。若当前前端明确调用的精确 `METHOD + path` 在 pinned 目标版本上经过带真实 owned fixture 的 GitHub-hosted 重测仍返回路由级 404/405，应作为 `runtime_rejected_routes` frontend false positive 保留运行证据并从 merged target catalog 抑制，禁止为了覆盖率把它伪标为 `runtime-verified`。写接口的 schema 默认只来自前端显式对象、编辑器模型或后端无副作用校验；只读 GET 可用于交叉验证字段名和类型。只有实例所有者**明确授权有界行为探针**时，才允许执行写 handler，并且必须同时满足：仅操作本次新建且带唯一测试前缀的 disposable 资源；调用前后核对业务资源基线；生产 Lucky、生产证书、生产 Docker daemon 和真实业务设备不得仅为覆盖率参与高风险验证；`prune`、批量删除、自更新、restore、2FA、reboot、destructive certificate 等全局危险路径必须迁入 GitHub-hosted disposable Lucky、private DinD 或 owned synthetic fixture；测试完成后立即清理并验证恢复。除非有明确后端校验证据，不要擅自把字段标为 required。
4. 推送证据/生成器变更后，通过 GitHub Actions 的 `render-artifacts` 手动工作流在云端运行 `tools/render_lucky_artifacts.py`，由 bot 只提交 `docs/generated/api-routes.md` 与 `openapi/lucky-v3.openapi.json`；不要手工批量改生成文件。
5. 审核 bot 生成的 diff，特别注意 route confidence、URL、token、域名、配置值和风险等级变化。
6. 推送分支并以 GitHub Actions 作为权威验证环境；`docs-ci` 必须通过 Python 3.10–3.13、repository verifier、测试、extractor、VitePress/Worker build。涉及行为 probe 的改动还必须通过对应的 disposable CI workflow。verifier 必须确认默认合并目录不残留 `unknown`。
7. 在 PR 中写明 Lucky 版本、镜像类型、bundle 数量、运行时验证方法，以及实际执行过的只读请求和任何获授权 disposable 写探针范围；不得只写“已验证”而省略真实调用边界。

不要仅为了让快照“更完整”而对**现有业务资源**调用删除、启停、同步、触发任务、终端、上传、下载、恢复或 Docker 写操作。上面的显式授权隔离 schema-probe 例外不得扩展到现有业务对象，也不得把生产级全局危险动作直接打到真实后端。恢复未知 HTTP 方法时，若已经在目标版本上校准确认路由器会在业务 handler 前执行鉴权，可优先使用**不带 OpenToken**的 method probe；非 404 只能证明 `METHOD + path` 被路由接受，不能证明请求体或业务成功语义。

`tools/lucky_web_rule_smoke.py` 是历史生产式 smoke 工具，不应作为常规回归路径。新增或重跑行为覆盖时优先建立 GitHub-hosted disposable fixture；只有实例所有者明确要求对受控实例执行该 smoke、已有配置基线并准备人工处理清理失败时才可使用。
