# 安装

Lucky Skills 的核心 CLI 只依赖 Python 标准库，正常使用**不需要 `pip install` 或 Node.js**。

## 前置条件

- Python 3.10 或更高版本；
- 一台你拥有或获授权管理的 Lucky v3 实例；
- Lucky 面板地址、安全入口和 OpenToken。

::: warning OpenToken 是管理员密钥
不要把 OpenToken 写入 Git、`.env`、shell 历史、Issue、聊天截图或公共日志。
:::

## 1. 获取项目

```bash
git clone https://github.com/fyzure/lucky-skills.git
cd lucky-skills
```

如果只使用 CLI / Agent Skill，到这里不需要安装任何 Python 包。

## 2. 配置 Lucky 凭据

推荐使用仓库自带的交互式安装器：

```bash
python3 tools/lucky_credentials.py install
```

安装器会要求输入包含安全入口的基础 URL，并交互式读取 OpenToken。

基础 URL 正确示例：

```text
https://lucky.example.com/<安全入口>
http://127.0.0.1:16601/<安全入口>
```

不要填写成：

```text
https://lucky.example.com
https://lucky.example.com/<安全入口>/api
```

默认仅允许 HTTPS；HTTP 只对回环地址放行。受控局域网必须使用 HTTP 时，可显式启用：

```bash
python3 tools/lucky_credentials.py install --allow-http
```

## 3. 检查凭据安装

```bash
python3 tools/lucky_credentials.py doctor
```

`doctor` 会检查凭据文件、权限和 URL，但不会显示 OpenToken 原文。

默认凭据位置和自定义路径说明见 [凭据管理](credentials.md)。

## 4. 验证 API 连通性

先只执行无副作用请求：

```bash
python3 tools/lucky_api.py status
python3 tools/lucky_api.py info
python3 tools/lucky_api.py modules
```

典型成功响应为 JSON 对象并包含 `ret: 0`。

如果失败，优先查看 [快速开始](quickstart.md) 中的常见错误表，以及 [鉴权与安全](authentication.md)。

## 5. 在 Codex / DevSpace 中使用

本仓库已经包含：

```text
.agents/skills/lucky/SKILL.md
```

在 Codex / DevSpace 中直接打开本仓库即可自动发现，也可以显式使用 `$lucky`。

插件安装应包含整个仓库，不要只复制 `SKILL.md`。

## 多实例或临时凭据

显式指定另一份凭据：

```bash
python3 tools/lucky_api.py --credentials-file /path/to/credentials.json status
```

一次性终端也可以使用环境变量；两个变量必须同时存在：

```bash
export LUCKY_BASE_URL='https://lucky.example.com/<安全入口>'
read -rsp 'Lucky OpenToken: ' LUCKY_OPEN_TOKEN
export LUCKY_OPEN_TOKEN
printf '\n'
python3 tools/lucky_api.py status
unset LUCKY_OPEN_TOKEN LUCKY_BASE_URL
```

更多凭据说明见 [凭据管理](credentials.md)。

## 升级

更新代码后重新验证即可：

```bash
git pull --ff-only
python3 tools/lucky_api.py status
```

本地只做连通性/只读调用即可；仓库一致性检查、测试、frontend extractor 回归和文档构建/部署以 GitHub Actions `docs-ci` 为权威结果。涉及 disposable 行为 probe 的改动还应等待对应 `lucky-*-ci` workflow 通过。更新代码本身不会自动修改 Lucky 配置。
