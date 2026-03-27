# Claws-Defender

<p align="center">
  <strong>为 OpenClaw agent 提供运行时防护。</strong>
</p>

**Claws-Defender** 是一个 OpenClaw 运行时安全插件。
它用于拦截危险工具调用、阻断恶意记忆写入、检测提示注入与危险 Shell 载荷、执行安全扫描，并把安全事件记录到本地审计日志。

如果你的 OpenClaw agent 具备文件访问、Shell 执行、网络外连或持久化记忆能力，这个插件可以在这些高风险面上增加一层实用的运行时防护。

[English](./README.md) | 中文

## 为什么需要它

OpenClaw 的强大来自 agent 可以真正执行动作。
但这也意味着提示注入、通过记忆文件持久化投毒、危险 Shell 执行，以及数据外传，都会变成实际的运行风险。

Claws-Defender 主要覆盖这些运行时场景：

- 在执行前拦截高风险命令
- 检测消息输入和持久化记忆中的 prompt injection
- 阻断写入 `MEMORY.md` 和 `memory/*.md` 的危险内容
- 提供快速扫描和完整扫描
- 通过追加写入的本地审计日志保留告警、扫描和阻断记录

## 核心亮点

- **before-tool-call 防护**：拦截反弹 Shell、危险外传、敏感文件读取等高风险命令
- **记忆写入防护**：在内容写入 `MEMORY.md` 或 `memory/*.md` 前先做静态正则与大模型语义 (LLM Semantic) 双重扫描
- **大模型意图识别**：对记忆写入进行深度意图和上下文分析，智能阻断混淆或复杂的 Prompt Injection 变体
- **跨行 Shell 载荷检测**：能识别被换行拆开的 `curl ... \n| sh` 和多行 reverse shell 片段
- **工作区安全扫描**：支持 quick scan 和 full scan，覆盖配置、记忆、凭据、session 与技能代码
- **本地审计日志**：将告警和阻断结果写入本地 JSONL，并自动脱敏

## 它保护哪些位置

```text
输入消息 / 工具输出 / 生成内容
              │
              ▼
     ┌──────────────────────┐
     │   Claws-Defender     │
     │    runtime guard     │
     └──────────┬───────────┘
                │
   ┌────────────┼────────────┐
   ▼            ▼            ▼
before_tool   记忆写入      安全扫描
拦截          MEMORY.md     工作区检查
              memory/*.md
```

## 核心能力

### 1. 工具调用拦截

插件会在 `before_tool_call` 阶段，对即将执行的命令做风险判断。

当前重点覆盖：

- `/dev/tcp`、`nc -e`、`bash -i >&` 等反弹 Shell
- `curl | sh`、`wget | bash` 这类远程下载即执行
- `crontab`、SUID 变更、`rm -rf /` 等持久化或破坏性命令
- `/etc/shadow`、`~/.ssh`、`~/.aws`、OpenClaw 凭据目录等敏感文件读取
- 文件读取后紧接网络外连的可疑行为模式

### 2. 记忆写入防护

持久化记忆是最容易把一次注入变成长期污染的入口之一，因此插件会保护：

- `MEMORY.md`
- `memory/*.md`

在内容写入这些文件之前，会扫描：

- prompt injection 指令
- system prompt 边界伪造
- 角色重定义
- 隐蔽或持久化行为指令
- 危险 Shell 载荷，包括跨行拆分的命令片段
- **(New!) LLM 语义分析**：通过引入 `MemorySemanticAnalyzer`，理解复杂指令的上下文意图，自动识别逃避静态规则的高级攻击。

命中危险静态规则或被大模型高置信度判定为恶意的记忆写入会在落盘前被直接阻断。

### 3. 安全扫描

插件提供两种扫描模式：

- `guard_quick_scan`：适合日常快速检查
- `guard_full_scan`：覆盖更广，适合系统性审计

快速扫描覆盖：

- 插件入口完整性基线
- 危险配置项检查
- 最近修改的技能代码
- `MEMORY.md` 与 `memory/*.md` 中的 prompt injection
- 记忆文件中的危险 Shell 载荷

完整扫描覆盖：

- 全量技能代码深度扫描
- 依赖审计
- session 历史扫描
- 凭据与权限检查
- 近期工具调用行为分析

### 4. 审计日志

安全事件会写入本地追加式审计日志：

```text
~/.openclaw/claws-defender/claws-defender-audit.jsonl
```

默认会做脱敏处理：

- 明显敏感信息会被替换
- 超长内容会被截断
- 只保留必要元数据和预览内容

## 可用 Agent Tools

- `guard_quick_scan`：执行快速安全扫描
- `guard_full_scan`：执行完整安全扫描
- `guard_status`：查看最近一次扫描结果
- `guard_explain`：按 finding ID 查看详细解释

示例提示词：

```text
运行一次安全扫描
做一次完整安全审计
最近一次扫描发现了什么？
解释一下 finding mem-cmd-reverse-shell:MEMORY.md:12
```

## 安装

该插件通过本地源码方式安装：

```bash
git clone https://github.com/Ch1nfo/claws-defender /tmp/claws-defender
cd /tmp/claws-defender
npm install
npm run build
openclaw plugins install /tmp/claws-defender
```

## 环境要求

- OpenClaw >= `2026.3.23-1`
- Node.js 与 npm，用于本地构建

## 项目定位

Claws-Defender 不是完整沙箱，也不是 OpenClaw 原生安全模型的替代品。
它更像是一层运行时安全护栏，用来尽早发现明显危险行为、降低持久化污染风险，并通过扫描和日志提升可观测性。

## 许可证

MIT。见 [LICENSE](./LICENSE)。
