# 资料来源

## 官方来源

- [Lucky 官方仓库](https://github.com/gdy666/lucky)：说明 Lucky 的功能、默认端口、前后端分离架构，以及第三方开发者可使用 OpenToken 调用接口。仓库也声明后续版本不再继续开源。
- [Lucky 官方文档](https://lucky666.cn/)：安装、模块与基础使用说明。
- [Lucky v2 更新日志](https://lucky666.cn/docs/updatelogs/v2.X/)：OpenToken 失败保护、CORS 策略和各模块版本演进。
- [Lucky 官方安装文件仓库](https://github.com/gdy666/lucky-files)：用于历史版本交叉核对。

## 当前证据来源

仓库的 Lucky 3.0.0 结论不再只依赖早期的只读实例观察，而是由三层证据合并：

1. **前端静态快照**：从已验证 Lucky 3.0.0 前端递归提取 API 调用、请求模型和 bundle SHA-256，生成 `evidence/lucky-v3-endpoints.json`；仓库不保存原始 bundle、OpenToken、安全入口或完整业务响应。
2. **脱敏运行时证据**：`evidence/lucky-v3-runtime-verification.json` 记录授权只读探针、一次性 TEST 资源 CRUD/行为探针及其字段形状、状态机和清理结果；秘密值、真实业务标识、证书私钥、Token 和配置备份正文不进入 evidence。
3. **GitHub-hosted disposable CI**：高风险、高权限或需要可控网络/设备的数据面验证统一放到 fresh Lucky / private DinD / Docker `--internal` / FUSE 专用容器 / owned virtual fixture 中执行。主密码与 2FA、`reboot_program`、配置 restore/import、自更新 failure semantic、真实 Docker prune、证书 destructive、OAuth/OIDC、NAT-PMP、UPnP、WOL powered-state、Rclone SystemMount 等均有独立 CI 行为证据；此外 `lucky-route-method-ci` 在不登录、不启用 OpenToken 的 fresh pinned Lucky 内网 fixture 中，用随机 missing-route 404 控制校准方法存在性，危险路由也只允许停在鉴权门。`lucky-docker-remaining-routes-ci` 则把 Lucky 连接到 private DinD，并用真实 owned BusyBox container 证明两条残留 Docker frontend call 在 Lucky 3.0.0 后端仍为 HTTP 404，从而作为 `runtime-rejected` false positive 抑制而不是伪装成已实现路由。

少量早期低风险或业务语义探针曾在实例所有者明确授权的现有 Lucky 上执行，并通过唯一 TEST 资源、最小变更和基线恢复约束风险；这些历史证据不会被解释为“以后应在生产环境重复验证”。当前需要破坏性、高权限或全局状态变更的覆盖一律优先使用 disposable CI。

对应 workflow 包括 `lucky-core-admin-ci`、`lucky-config-restore-ci`、`lucky-update-ci`、`lucky-docker-prune-ci`、`lucky-ssl-destructive-ci`、`lucky-oauth-ci`、`lucky-natpmp-ci`、`lucky-upnp-ci`、`lucky-wol-ci`、`lucky-rclone-mount-ci`、`lucky-storage-mount-ci`、`lucky-route-method-ci`、`lucky-docker-remaining-routes-ci` 等；`docs-ci` 负责 Python 3.10–3.13 仓库验证、VitePress/Worker 构建与文档部署。

## 历史源码的使用方式

Lucky 官方仓库公开到较早版本。历史源码可证明某些长期约定，例如 `/api/...` 路由、JSON `ret` 包络和前后端分离模式，但不能用来断言 Lucky v3 的当前请求体或权限行为。v3 结论优先级为：**当前版本前端证据 + 对应运行时/CI 行为证据 > 当前官方文档 > 历史源码**。如果不同来源冲突，以版本绑定且可重复的运行时结果为准，并把失败语义、平台边界或授权门槛原样记录，而不是补成推测的“成功行为”。
