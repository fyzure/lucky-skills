# WebService 反向代理语义

本页记录 Lucky **3.0.0 wanji** 的 WebService `reverseproxy` 行为。结论同时来自当前前端编辑器模型和获授权实例上的有界运行时探针，不把 Lucky 的 `NginxConf` 当作完整 Nginx 兼容层。

## 已验证范围

当前已实际验证：

- WebService 子规则的完整父对象写入流程；
- 前端路径前缀与后端基础路径的拼接；
- `NginxConf` 的请求头、响应头、重定向与路径匹配指令；
- 编辑器列出的常用变量；
- `UseTargetHost`；
- `AddProtoToHeader` / `ProtoHeaderKey`；
- `AddRemoteIPToHeader` / `AddRemoteIPHeaderKey`；
- `AutoProxyLocation` / `AutoProxyLocationWithoutSameHost`；
- `proxy_redirect off;` / `proxy_redirect default;` 的兼容行为。

运行时验证只保留通用语义和布尔结果，不保存真实业务域名、RuleKey、客户端地址、OpenToken 或 Lucky 自动生成的真实 token。

## 子规则不是独立资源

Lucky 当前前端保存子规则时采用的是**完整父规则替换**：

```text
GET /api/webservice/rule/{RuleKey}
        ↓
保留完整父规则对象
        ↓
修改 DefaultProxy 或 ProxyList
        ↓
PUT /api/webservice/rule/{RuleKey}
```

新增或复制一个子规则时，前端会把新对象加入 `ProxyList`，新对象没有现成 `Key`；Lucky 持久化后再分配 Key。

因此自动化不要假设存在“只 PATCH 一个子规则”的稳定接口，也不要拿一小段 JSON 覆盖父对象。父规则同时包含监听、TLS、WAF、认证、日志、缓存、限流等大量字段。

::: warning 全对象 PUT 有并发覆盖风险
写入前应重新 GET 最新父规则，只修改目标字段并保留所有未知字段。失败回滚时也不要无条件 PUT 一个很早以前保存的旧快照，否则可能覆盖别人刚完成的业务修改。
:::

一次性测试资源的清理更适合采用：

```text
重新 GET 最新父规则
→ 只移除自己唯一 TEST 前缀对应的子规则
→ PUT 最新对象
→ GET 验证 TEST 子规则为 0
```

## 前端路径与后端路径

`Domains` 可以带前端路径，`Locations` 也可以带后端基础路径。例如：

```json
{
  "Domains": ["example.com/app"],
  "Locations": ["https://backend.example/base"]
}
```

实测请求：

```text
https://example.com/app/api/user?x=1
```

会把 `/app` 作为前端匹配前缀移除，再把剩余路径拼到后端已有的 `/base`：

```text
https://backend.example/base/api/user?x=1
```

Query 保持不变。

`NginxConf` 里的 `location` / `path` 匹配使用的是**移除前端路径后的请求路径**。所以上例中的：

```nginx
location /api/ { add_header X-Api yes always; }
```

能够匹配 `/app/api/user`。

但变量的观察位置不同：在同一次探针中，`$request_uri`、`$uri`、`$document_uri` 仍然包含前端 `/app`；其中 `$request_uri` 还保留 Query。不要把“路径匹配使用剥离后的路径”和“所有 URI 变量都已剥离”混为一谈。

## `NginxConf` 支持的指令

Lucky 前端把这个字段称为“自定义配置”。当前 3.0.0 编辑器明确列出以下语法，运行时探针也已覆盖其核心行为：

| 指令 | 已验证语义 |
| --- | --- |
| `proxy_set_header Header Value;` | 设置发往后端的请求头；Value 为 `""` 时删除该请求头 |
| `proxy_hide_header Header;` | 从返回给客户端的响应中移除指定后端响应头 |
| `add_header Header Value [always];` | 添加响应头；无 `always` 时只对 Lucky 列出的成功/重定向状态生效，`always` 对错误状态也生效 |
| `proxy_redirect From To;` | 改写后端 `Location` 和 `Refresh` 中匹配的重定向地址 |
| `location ... { 指令; }` | 按移除前端路径后的请求路径应用内部指令 |
| `path ... 指令;` | Lucky 自己的路径简写语法 |

每条指令以 `;` 结束；前端还明确支持 `#` 注释和用引号包裹包含空格的值。

这不是任意 Nginx 配置入口。只使用当前编辑器明确支持、且在目标 Lucky 版本上验证过的指令。

## 任意请求头注入

需要给后端写固定 Header 时，不必依赖 `AddProtoToHeader` 之类的专用字段，可以直接使用：

```nginx
proxy_set_header X-Workspace-Id lq-devspace;
proxy_set_header X-Forwarded-Prefix /lq;
```

固定字符串、带空格的引号值和变量值都已实测成功。例如：

```nginx
proxy_set_header X-Method $request_method;
proxy_set_header X-Origin-Host $host;
proxy_set_header X-Client-Header $http_x_example;
```

删除客户端原有请求头：

```nginx
proxy_set_header X-Unwanted "";
```

::: danger 不要拼接不可信输入
`NginxConf` 是强配置字段，不是面向最终用户的模板语言。不要把未审查的用户名、路径、Header 值或其他外部输入直接拼进指令字符串。
:::

## 当前变量集合

Lucky 3.0.0 前端列出的常用变量为：

```text
$host
$http_host
$scheme
$request
$request_method
$request_uri
$uri
$document_uri
$args
$query_string
$is_args
$remote_addr
$remote_port
$server_port
$http_upgrade
$connection_upgrade
$proxy_add_x_forwarded_for
$http_<请求头名>
```

最终运行时验证中，`$connection_upgrade` 在携带 `Upgrade: websocket`、`Connection: Upgrade` 的请求上展开为 `upgrade`；`$proxy_add_x_forwarded_for` 会在已有 X-Forwarded-For 后追加当前连接地址。

## `location` 和 `path`

### `location`

当前编辑器与运行时验证覆盖：

```nginx
location /api/ { add_header X-Prefix yes always; }
location = /exact { add_header X-Exact yes always; }
location ~ ^/v[0-9]{1,2}/ { add_header X-Regex yes always; }
location ~* ^/CASE/ { add_header X-Regex-I yes always; }
location !~ ^/blocked/ { add_header X-Negative yes always; }
```

分别对应前缀、精确、正则、忽略大小写正则和负向正则匹配。

### Lucky `path` 简写

当前实测支持：

```nginx
path /api/* add_header X-Wild yes always;
path regexp:^/rx[0-9]+/ add_header X-Regex yes always;
path !!!/deny/* add_header X-Negative yes always;
```

即 `*` 通配、`regexp:` 正则和 `!!!` 取反。

## 响应头与 `proxy_redirect`

运行时验证确认：

```nginx
proxy_hide_header X-Upstream-Secret;
add_header X-Default default;
add_header X-Always always always;
proxy_redirect http://backend/ /rewritten/;
```

其中：

- `proxy_hide_header` 会真正从客户端收到的响应中去掉后端 Header；
- `add_header` 无 `always` 时在 200 上存在、在 418 上不存在；
- 带 `always` 的 Header 在 200 和 418 上都存在；
- 显式 `proxy_redirect From To` 同时改写 `Location` 与 `Refresh`。

前端也接受：

```nginx
proxy_redirect off;
proxy_redirect default;
```

当前探针中 `off` 保留原始地址；`default` 也表现为兼容占位，即使重定向目标与当前后端 Host 相同也保持原始地址。不要把 Lucky 的 `default` 自动理解为 Nginx `proxy_redirect default` 的完整实现。

## `UseTargetHost`

实测：

| 值 | 后端收到的 `Host` |
| --- | --- |
| `true` | `Locations` 目标 URL 的 Host |
| `false` | 前端请求的 Host |

如果后端按 Host 做虚拟主机路由，或者需要让应用知道真实公开域名，这个开关会直接改变行为。

## 协议与客户端 IP Header

专用字段仍然适合简单场景：

```json
{
  "AddProtoToHeader": true,
  "ProtoHeaderKey": "X-Forwarded-Proto",
  "AddRemoteIPToHeader": true,
  "AddRemoteIPHeaderKey": "X-Real-IP"
}
```

在 HTTPS 前端实测前者写入 `https`，后者写入当前客户端地址。

如果需要固定 Header、组合多个 Header 或指定常量值，则使用 `NginxConf` 的 `proxy_set_header` 更直接。

## 自动反代重定向

`AutoProxyLocation` 不是简单的字符串 `proxy_redirect`。

当前 3.0.0 运行时行为：

| 配置 | 同后端 Host 重定向 | 不同 Host 重定向 |
| --- | --- | --- |
| `AutoProxyLocation=false` | 保留原始 URL | 保留原始 URL |
| `AutoProxyLocation=true` | 自动改写 | 自动改写 |
| 再加 `AutoProxyLocationWithoutSameHost=true` | 保留原始 URL | 自动改写 |

自动改写后的地址位于当前前端域名和前端路径下面，形状类似：

```text
https://<frontend>/<prefix>/lucky_auto_reverseproxy_<opaque-token>/...
```

`<opaque-token>` 是 Lucky 生成的内部标识，不应由调用方解析或持久化。

## 推荐的安全写入流程

修改已有 WebService：

```text
1. GET /api/webservice/rule/{RuleKey}
2. 审阅完整父规则
3. 临写前再次 GET，避免长时间持有旧快照
4. 只修改目标 DefaultProxy / ProxyList 字段
5. PUT 完整父规则
6. GET 回读目标字段和新 Key
7. 从真实客户端验证 DNS、TLS、路径、Header 和后端响应
```

如果 Lucky 返回 429，不要盲目重复 PUT。写操作默认不会由 `LuckyClient` 自动重试；先 GET 当前状态确认前一次是否已经生效，再决定下一步。

## 可重复的语义探针

仓库提供：

```text
tools/lucky_web_reverseproxy_probe.py
```

它用于**实例所有者明确授权的集成验证**，不是普通健康检查。探针要求：

- 一个已有的 TLS WebService 父规则；
- 一个已经解析并被证书覆盖的通配 DNS 后缀；
- 本机能通过指定地址访问该 Lucky HTTPS 监听；
- 能访问外部 HTTPS echo/redirect origin。

示例：

```bash
python3 tools/lucky_web_reverseproxy_probe.py \
  --confirm PROBE-AND-CLEAN-WEB-REVERSE-PROXY \
  --rule-key '<reviewed-rule-key>' \
  --domain-suffix 'rs.example.com'
```

工具会在**一次 setup PUT** 中加入唯一 `TEST-lucky-skills-websem-*` 子规则，完成行为验证后重新读取最新父规则，并在**一次 cleanup PUT** 中只删除自己的 TEST 子规则。清理遇到 Lucky 429 时会有限退避重试；不会把旧父规则快照直接覆盖回去。

输出只包含布尔结果、抽象路径/重定向分类和清理计数，不主动打印 OpenToken、真实临时 Host、客户端 IP 或 Lucky 自动生成的真实 token。

::: warning 外部 echo 服务
默认探针会把专门构造的测试请求发给 `https://httpbin.org`。不要把任何业务 Cookie、Authorization、私密 Header 或其他秘密放进探针请求。需要更严格的数据边界时，可通过 `--echo-origin` 指向你自己控制的等价 HTTPS echo 服务。
:::

## 版本边界

这些语义绑定于当前 **Lucky 3.0.0** 前端快照和运行时证据。升级 Lucky 后应重新提取前端资产并重新运行受控验证；在新版本重新验证前，不要默认继承 `NginxConf` 解析器、自动重定向路径或全对象写入细节。
