# 安全 API 客户端与 CLI

`lucky_api` 是无第三方依赖的 Python 客户端，`tools/lucky_api.py` 是它的命令行入口。两者共同解决鉴权注入、路径拼接、错误判断、限流重试、响应上限和写操作保护；它们不会把 OpenToken 放进 URL 或命令行参数。

## 能力与边界

当前客户端支持：

- `GET`、`POST`、`PUT`、`DELETE` 和 `PATCH`；
- 重复查询参数、JSON 请求体、原始文件请求体和二进制下载；
- HTTP 错误、Lucky `ret` 业务错误、JSON 解码错误、传输错误和响应过大错误；
- `RateLimit-Limit`、`RateLimit-Remaining` 和 `RateLimit-Reset` 元数据；
- 只读请求遇到 429/502/503/504 时的有限重试；
- 基于当前 v3 前端静态快照 + 与该快照版本和 SHA-256 精确绑定的覆盖层做路径模板匹配、风险分级和部分请求/响应 schema 补全。
- CLI 的 JSON 显示默认递归脱敏常见密码、Token、Secret、私钥、2FA Key、安全入口等敏感内容，同时仍保留普通资源 `Key`、状态字段和非敏感配置供排查。

客户端不提供“自动猜测配置字段”、网页登录模拟、模块 2FA 绕过或批量试探接口。multipart 表单可作为原始请求体发送，但客户端不会替你构造包含密钥或文件的表单。

## 风险模型

每个实际的 `METHOD + path` 会先与合并后的证据目录匹配，再分为：

| 等级 | 含义 | 默认行为 |
|---|---|---|
| `read-only` | 快照中存在，且未识别出副作用 | 允许 |
| `mutating` | 修改配置、执行动作，或有副作用的 GET | 拒绝 |
| `dangerous` | 删除、重启、文件写入、恢复、Docker 操作等 | 拒绝 |
| `unknown` | 当前快照没有对应方法和路径 | 拒绝 |

这是保守策略，不是权限系统。运行时覆盖可以显式改写反常 GET 的风险，例如 `GET /api/configure`（配置 ZIP 备份）、`GET /api/ssl/download`、`GET /api/ipdb/download` 都不会因为使用 GET 就自动放行。`read-only` 仍可能返回日志、路径、IP、容器信息等敏感数据；Lucky 升级后也可能改变端点行为。

## CLI 快速使用

先安装凭据，再优先让 API CLI 在同一进程中读取私有凭据文件：

```bash
python3 tools/lucky_credentials.py install
python3 tools/lucky_api.py status
python3 tools/lucky_api.py info
python3 tools/lucky_api.py modules
```

CLI 只在 `LUCKY_BASE_URL` 与 `LUCKY_OPEN_TOKEN` 同时为非空值时使用环境凭据；两者都未设置/为空时自动使用平台/配置对应的默认凭据文件。只有一个非空时会 fail-closed，避免写操作误用另一套默认凭据。`--credentials-file PATH` 可显式覆盖。`lucky_credentials.py run -- ...` 仍保留兼容，但会把凭据注入子进程环境。

查看状态码、内容类型和限流元数据：

```bash
python3 tools/lucky_api.py status --show-meta
```

CLI 打印 JSON 时默认使用客户端的 display-safe 脱敏层，因此即使某个只读端点意外返回 OpenToken、密码、Secret、私钥或安全入口，也不会直接回显到终端日志。Python 库的 `request_json()` 仍返回服务器原始对象，不会静默改写业务数据；调用方需要自己决定如何存储和展示。

只有在明确需要逐字检查原始 JSON、且确认当前终端/日志环境安全时，才使用：

```bash
python3 tools/lucky_api.py call /api/some-readonly-route --show-secrets
```

`--show-secrets` 只影响终端 JSON 显示，不改变请求风险分级。`--output FILE` 仍按原始字节保存响应，以便二进制下载和精确取证；如果目标是 JSON，请把输出文件本身按敏感数据处理。

## 查询路由目录

目录查询不需要 OpenToken：

```bash
python3 tools/lucky_api.py catalog --search docker --method GET
python3 tools/lucky_api.py catalog --module ddns --risk mutating
python3 tools/lucky_api.py catalog --search logs --json
```

目录输出包括方法、路径模板、模块、风险、查询字段、请求体字段、请求体 JSON Schema/Content-Type、响应类型/已验证媒体类型、响应 schema、schema 证据和路由证据等级。默认加载 `evidence/lucky-v3-endpoints.json` 后，会自动叠加同目录、且 `target.version` 与 `static_snapshot_sha256` 都精确匹配的 `lucky-v3-runtime-verification.json`；显式 `--catalog-file` 指向该静态快照时也会应用同目录运行时文件。任一绑定不匹配都会 fail-closed。字段为空表示当前证据无法恢复，不代表请求体确实没有字段。

当前 Lucky 3.0.0 运行时覆盖已把静态快照中的 41 条 `UNKNOWN` 全部归类或抑制为字面量误报，默认目录应返回 0 条 unknown：

```bash
python3 tools/lucky_api.py catalog --risk unknown --json
```

`runtime-verified` 只表示方法/路由或受控 GET 行为已经在授权实例上确认，不代表所有请求体字段、WebSocket 协议或成功响应 schema 都已完整恢复。请求体补全另看 `schema_evidence`：例如前端模型直传、前端显式对象构造、授权只读 GET 的字段名/类型交叉验证，或在实例所有者明确授权后对新建一次性资源执行并立即清理的有界 API 写探针。当前 OpenAPI 已能表达 object、`array<string>`、multipart binary、octet-stream、嵌套对象、动态 map、enum 与数值上下界。Lucky 3.0.0 的“有请求体但字段/schema 为空”缺口已从 122 条降到 0 条；进一步的类型化覆盖按 merged catalog 统计：当前共有 **243 条 POST/PUT/PATCH**，其中 **219 条**标记 `has_body=true` 并在 OpenAPI 生成 `requestBody`；这 219 条中，顶层仍含未类型化属性的操作已压到 **1 条**，全路由显式 response schema 已提升到 **346 条**。当前 extractor 还会保守识别首参可静态还原到 `api/...` 的直接 `client.get/post/put/delete/patch(...)` 调用，因此当前 Docker UI 的 multipart `images/upload-temp` 不再落出 catalog。当前已优先补深 DDNS、WebService、Docker、FRP、SSL/ACME、Security Groups、IPFilter/PortTrap、PortForward、STUN，并继续覆盖 Rclone、Cron、WOL、StorageManagement、FileBrowser、Status、IPDB、IconLib、Modules/About 与 Frontend Preferences 的运行时响应；运行时 GET 只保留字段名/JSON 类型，动态 RuleKey、域名、容器/网络标识、路径和秘密值都不进入证据文件。受保护 response schema 还会由 verifier 递归扫描 combinator/list 分支，禁止重新文档化 password/secret/private-key 字段。最后 6 条 Docker legacy wrapper 仍只记录隔离 BusyBox probe、请求校验差异或非破坏性 mock Docker API 实际证明的字段，不扩展推测字段。

## 查询参数与二进制响应

重复使用 `--query KEY=VALUE`，客户端负责 URL 编码：

```bash
python3 tools/lucky_api.py call /api/docker/containers \
  --query all=true --query includeStats=false
```

下载端点应写入文件；二进制内容默认不会直接打印到交互终端：

```bash
python3 tools/lucky_api.py call '/api/docker/containers/ID/export' \
  --method POST --output container.tar \
  --allow-write --confirm 'POST /api/docker/containers/ID/export'
```

上例只是调用语法，导出操作可能很耗资源；请把 `ID` 替换为已核对的目标，并先确认磁盘空间和数据处理要求。

## JSON 与原始请求体

请求体优先从文件或标准输入读取，避免敏感字段出现在 shell 历史和进程参数中：

```bash
python3 tools/lucky_api.py call /api/ddns --method PUT \
  --json-file reviewed-ddns.json \
  --allow-write --confirm 'PUT /api/ddns'

python3 tools/lucky_api.py call /api/ddns --method PUT --json-stdin \
  --allow-write --confirm 'PUT /api/ddns' < reviewed-ddns.json
```

写操作需要两个独立条件：`--allow-write`，以及与实际请求完全相同的 `--confirm 'METHOD /api/path'`。这只能防止误操作，不能替代备份、差异审阅和回滚计划。

原始内容可通过 `--raw-file` 和 `--content-type` 发送。JSON 与原始请求体互斥。

## 可逆 Web 规则写入测试

`tools/lucky_web_rule_smoke.py` 是专门验证 Web 服务规则写入链路的集成测试。它执行：

```text
读取基线 → POST 创建禁用规则 → GET 列表定位 → GET 详情回读
         → DELETE 删除规则 → GET 确认基线恢复
```

测试对象固定为禁用状态、仅绑定 `127.0.0.1`、关闭 TLS 和自动防火墙、无域名、无路径、无子规则、无代理目标。清理位于 `finally` 中；即便主验证失败，也会再次按唯一名称查找并尝试删除测试规则。

该测试会真实修改 Lucky 配置，只能在明确授权、已备份且有人值守时运行：

```bash
python3 tools/lucky_credentials.py run -- \
  python3 tools/lucky_web_rule_smoke.py \
  --confirm CREATE-AND-DELETE-DISABLED-WEB-RULE
```

当前 Lucky 3.0.0 实例已实际通过该流程。实测后规则数量和原有 RuleKey 集合恢复，测试名称无残留，16666 未监听，iptables/nftables 未出现 16666 规则。此结果只证明禁用规则的创建、读取和删除链路，不证明启用监听、TLS、域名匹配或反向代理流量链路。

## WebService 反向代理语义探针

`tools/lucky_web_reverseproxy_probe.py` 用于继续验证上一节没有覆盖的**真实 reverseproxy 行为**。它要求实例所有者明确授权，并复用一个已经存在的 TLS WebService 父规则；不会新开监听端口或自动修改防火墙。

探针把多个唯一 `TEST-lucky-skills-websem-*` 子规则合并到**一次 setup PUT** 中，验证完成后重新读取最新父对象，再用**一次 cleanup PUT** 只移除自己的 TEST 子规则。这样既符合 Lucky 前端“完整父规则 → 修改 `ProxyList` → PUT 父规则”的保存模型，也显著降低连续写入触发 429 的概率。清理遇到 429 时会有限退避；它不会把启动时保存的旧父规则快照直接覆盖回去。

验证范围包括 `NginxConf` 的任意请求头写入/删除、响应头隐藏与追加、`Location` / `Refresh` 改写、`location` / `path` 匹配、前端路径剥离和后端基础路径拼接，以及 `UseTargetHost`、协议/IP Header helper 和自动反代重定向。完整行为表见 [WebService 反向代理语义](./webservice-reverse-proxy.md)。

示例：

```bash
python3 tools/lucky_web_reverseproxy_probe.py \
  --confirm PROBE-AND-CLEAN-WEB-REVERSE-PROXY \
  --rule-key '<reviewed-rule-key>' \
  --domain-suffix 'rs.example.com'
```

`--domain-suffix` 必须已经由该 WebService 的证书和 DNS 覆盖。默认使用 `https://httpbin.org` 作为专门的 echo/redirect 测试后端；不要把业务 Cookie、Authorization 或私密 Header 带入探针。需要自有测试后端时可通过 `--echo-origin` 替换。

该工具输出布尔验证项、脱敏后的路径/重定向分类和清理计数，不主动打印 OpenToken、临时 Host、客户端 IP 或 Lucky 自动生成的真实重定向 token。

## Web 服务 307 / 308 重定向

Lucky v3 的重定向状态码位于 Web 服务对象的嵌套字段：

```text
DefaultProxy.OtherParams.RedirectType
```

对普通子规则则位于该子规则自己的 `OtherParams.RedirectType`。Lucky 3.0.0 已通过 OpenToken API 实测接受 `"308"`。一个标准的 80 → HTTPS 永久跳转至少应保持这些语义：

```json
{
  "ListenPort": 80,
  "Enable": true,
  "EnableTLS": false,
  "DefaultProxy": {
    "WebServiceType": "redirect",
    "Locations": ["https://{host}{path}{args}"],
    "OtherParams": {
      "RedirectType": "308"
    }
  }
}
```

上面只是关键字段，不是可直接覆盖现有规则的完整请求体。Lucky Web 规则对象包含大量监听、认证、日志、WAF、缓存和兼容字段；更新现有规则时应先 `GET /api/webservice/rule/{RuleKey}`，只修改目标字段，再把完整对象 `PUT` 回同一路径。新建监听器使用 `POST /api/webservice/rules`。

实测在 Lucky 3.0.0 上创建 `WebServiceType="redirect"`、`Locations=["https://{host}{path}{args}"]`、`RedirectType="308"` 的 80 端口规则后，GET 与 POST 请求均返回 `308 Permanent Redirect`，并保留 Host、Path 与 Query。

## Python 调用

```python
from lucky_api import LuckyClient, RouteCatalog

catalog = RouteCatalog.load_default()
client = LuckyClient.from_environment(
    catalog=catalog,
    timeout=10,
    retries=2,
    max_response_bytes=16 * 1024 * 1024,
)

status = client.request_json("GET", "/api/status")
print(status["ret"])
```

调用方必须显式批准非只读操作：

```python
result = client.request_json(
    "PUT",
    "/api/ddns",
    json_body=reviewed_complete_object,
    allow_unsafe=True,
)
```

库层的 `allow_unsafe=True` 只表示调用代码已经完成外部审批；它不会弹出确认提示。面向人工操作时优先使用 CLI 的双重确认。

## 错误类型

调用方可分别处理：

- `UnsafeOperationError`：目录未知或操作不是只读；
- `TransportError`：DNS、连接、TLS 或超时失败；
- `HTTPStatusError`：HTTP 非成功状态；
- `LuckyAPIError`：HTTP 可为 200，但 JSON 中 `ret` 既不是常规成功值，也没有匹配该 `METHOD + path` 的运行时验证 `success_response_markers`；
- `ResponseDecodeError`：预期读取 JSON，但响应不是合法 JSON；
- `ResponseTooLargeError`：响应超过配置上限。

异常消息只包含 API 路径，不包含基础 URL、安全入口或 OpenToken。HTTP 错误正文最多保留一小段，并再次替换可能出现的 Token。

默认成功值仍是 `ret: 0`（或缺少 `ret`）。少数端点的闭源 v3 语义不同，例如本机 Lucky 3.0.0 已验证 `PUT /api/about-content` 在同值保存成功时返回 `ret: 1, msg: "成功"`。这种例外由运行时目录逐路由精确声明；同一路由若返回 `ret: 1` 但消息不同，客户端仍会按业务错误处理。

## 重试规则

只有风险为 `read-only` 的请求才会自动重试 429、502、503 和 504。客户端优先遵守 `Retry-After`，其次使用 `RateLimit-Reset`，否则指数退避；单次等待上限为 30 秒。

写操作、危险操作和未知操作永不自动重试。它们超时后应先查询当前状态，避免重复创建、重复触发或部分写入。

## 版本漂移

路由目录目标版本为 Lucky 3.0.0。升级 Lucky 后应重新提取前端资产、审核路由差异并重新生成文档；在新版本完成验证前，不应批准写操作。可用 `LUCKY_API_CATALOG` 指向另一个经过审核的证据 JSON。
