# Claws-Defender

中文 | [English](#english)

OpenClaw 运行时安全插件。它用于拦截高风险工具调用、检测提示注入、执行安全扫描，并把安全事件记录到本地审计日志。
已适配open claw v2026.3.23-1

## 中文

### 简介

Claws-Defender 是一个独立维护的 OpenClaw 运行时安全插件仓库，推荐通过 GitHub 仓库源码构建后再从本地目录安装。

它提供这些能力：

- 工具调用拦截：在执行前识别反弹 shell、可疑外传、凭据读取等高风险命令
- 提示注入检测：扫描收到的消息和 `MEMORY.md` 写入内容
- 双模式安全扫描：支持快速扫描和完整扫描
- 行为基线记录：分析近期工具调用中的异常模式
- 本地审计日志：将安全事件写入 `~/.openclaw/claws-defender/`

### 核心功能

如果你在 OpenClaw 中运行带文件系统、Shell 或网络能力的 agent，这个插件可以提供一层额外的运行时防护，帮助你更早发现危险配置、可疑技能代码和潜在数据泄露行为。

### 安装方式

这是一个本地安装插件。请把仓库放到任意目录下（如/tmp/claws-defender），再从本地路径安装。

安装步骤：
```bash
git clone https://github.com/Ch1nfo/claws-defender /tmp/claws-defender
cd /tmp/claws-defender
npm install
npm run build
openclaw plugins install /tmp/claws-defender
```

### 环境要求

- OpenClaw >= 2026.3.22
- Node.js 与 npm，可用于本地构建

### 可用工具

- `guard_quick_scan`: 快速安全扫描
- `guard_full_scan`: 完整安全扫描
- `guard_status`: 查看最近一次扫描结果
- `guard_explain`: 按 finding ID 查看详细解释

示例提示词：

```text
运行一次安全扫描
做一次完整安全审计
现在有哪些安全问题？
解释一下 finding cfg-gateway-auth-mode
```

### 扫描功能

快速扫描：

- 插件入口完整性基线
- 危险配置项检查
- 最近修改的技能代码扫描
- `MEMORY.md` 注入模式检查

完整扫描：

- 所有技能代码深度扫描
- 依赖漏洞检查
- Session 历史中的敏感信息扫描
- `~/.openclaw/credentials` 权限检查
- 近期工具调用行为分析

### 审计日志

日志文件位于：

```text
~/.openclaw/claws-defender/claws-defender-audit.jsonl
```

日志现在默认做脱敏处理，只保留必要元数据和截断后的内容预览，不会原样持久化完整消息正文或明显的敏感字段。

### 获取帮助

- 用 GitHub Issues 提交问题或误报
- 在 issue 中附上 OpenClaw 版本、插件版本、复现步骤和相关日志片段


### 许可证

MIT，见 [LICENSE](./LICENSE)。

---

## English

### What This Is

Claws-Defender is a standalone OpenClaw runtime security plugin repository. The recommended install flow is to clone the GitHub repo, build it locally, and install it from that directory.

It provides:

- Tool call interception for high-risk shell and file operations
- Prompt injection detection for inbound messages and `MEMORY.md` writes
- Dual-mode security scans: quick scan and full scan
- Behavioral baseline tracking for recent tool usage
- Local audit logging under `~/.openclaw/claws-defender/`

### Why It Is Useful

If your OpenClaw agents can access the filesystem, shell tools, or network tools, this plugin adds a practical runtime guard layer to catch dangerous configs, suspicious skill code, and possible exfiltration behavior earlier.

### Installation

This plugin is installed locally from source. Place the repository under any directory (e.g. /tmp/claws-defender), build it there, and install it from the local path.

Install steps:

```bash
git clone https://github.com/Ch1nfo/claws-defender /tmp/claws-defender
cd /tmp/claws-defender
npm install
npm run build
openclaw plugins install /tmp/claws-defender
```

### Requirements

- OpenClaw >= 2026.3.22
- Node.js and npm for local build

### Available Tools

- `guard_quick_scan`: run a quick security scan
- `guard_full_scan`: run a full security scan
- `guard_status`: inspect the latest scan result
- `guard_explain`: explain a finding by ID

Example prompts:

```text
Run a security scan
Do a full security audit
Are there any security issues right now?
Explain finding cfg-gateway-auth-mode
```

### Scan Coverage

Quick scan:

- plugin entry integrity baseline
- dangerous configuration checks
- recently modified skill code scan
- `MEMORY.md` injection pattern checks

Full scan:

- deep scan across all skill code
- dependency vulnerability audit
- sensitive data scan in session history
- permission audit for `~/.openclaw/credentials`
- recent tool-call behavior analysis

### Audit Log

Audit events are written to:

```text
~/.openclaw/claws-defender/claws-defender-audit.jsonl
```

The audit log is sanitized by default. It keeps necessary metadata and truncated previews instead of persisting full message bodies or obvious sensitive fields verbatim.

### Support

- Open a GitHub Issue for bugs, false positives, or installation problems
- Include your OpenClaw version, plugin version, reproduction steps, and relevant log excerpts


### License

MIT. See [LICENSE](./LICENSE).
