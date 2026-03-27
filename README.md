# Claws-Defender

<p align="center">
  <strong>Runtime guardrails for OpenClaw agents.</strong>
</p>

**Claws-Defender** is an OpenClaw runtime security plugin.
It intercepts dangerous tool calls, blocks malicious memory writes, detects prompt injection and hazardous shell payloads, runs security scans, and records security events to a local audit log.

If your OpenClaw agent can access files, shell commands, network egress, or persistent memory, this plugin adds a practical runtime defense layer around those surfaces.

[中文](./README_ZH.md) | English

## Why This Exists

OpenClaw is powerful because the agent can act.
That also means prompt injection, persistence through memory files, risky shell execution, and data exfiltration attempts all become real operational concerns.

Claws-Defender focuses on those runtime risks:

- high-risk command interception before execution
- prompt-injection detection on inbound content and persisted memory
- blocking dangerous writes to `MEMORY.md` and `memory/*.md`
- quick and full workspace security scans
- append-only local audit logging for alerts, scan results, and blocked actions

## Highlights

- **Before-tool-call guardrail**: blocks reverse shells, dangerous exfiltration patterns, sensitive file reads, and other suspicious command executions
- **Memory write protection**: scans content before it lands in `MEMORY.md` or `memory/*.md` using both static regex and LLM semantic analysis
- **LLM Semantic Intent Analysis**: deeply inspects writes for malicious context, neutralizing complex or obfuscated Prompt Injection attacks that evade standard rules
- **Workspace scanning**: supports quick scan and full scan flows for config, memory, credentials, sessions, and skill code
- **Local audit trail**: writes alerts and block decisions to a local JSONL audit log with secret redaction

## What It Protects

```text
Inbound message / tool output / generated content
                    │
                    ▼
         ┌──────────────────────┐
         │   Claws-Defender     │
         │  runtime guardrails  │
         └──────────┬───────────┘
                    │
     ┌──────────────┼──────────────┐
     ▼              ▼              ▼
 before_tool   memory writes    security scans
 interception  MEMORY.md        workspace checks
                memory/*.md
```

## Core Capabilities

### 1. Tool Call Interception

The plugin hooks into `before_tool_call` and evaluates risky commands before execution.

Current protections include:

- reverse shells such as `/dev/tcp`, `nc -e`, `bash -i >&`
- remote download-and-execute patterns such as `curl | sh` and `wget | bash`
- destructive or persistence-oriented commands such as `crontab`, SUID changes, and `rm -rf /`
- sensitive local reads such as `/etc/shadow`, `~/.ssh`, `~/.aws`, and OpenClaw credential paths
- suspicious multi-step behavior patterns such as file read followed by network egress

### 2. Memory Write Protection

The plugin protects persistent memory because memory poisoning is one of the easiest ways to turn a one-time injection into a durable compromise.

Before content is written to:

- `MEMORY.md`
- `memory/*.md`

it is scanned for:

- prompt injection directives
- system prompt spoofing
- role reassignment instructions
- hidden or persistent behavior directives
- dangerous shell payloads, including cross-line command fragments
- **(New!) LLM Semantic Analysis**: utilizes `MemorySemanticAnalyzer` to understand complex context and intent, catching sophisticated injection variants that bypass static matching.

Dangerous shell payloads or high-confidence malicious intents identified by the LLM are blocked before they persist.

### 3. Security Scanning

Two scan modes are available:

- `guard_quick_scan`: fast checks intended for routine use
- `guard_full_scan`: broader inspection across the workspace and recent runtime history

Quick scan coverage:

- plugin entry integrity baseline
- dangerous configuration checks
- recently modified skill code
- `MEMORY.md` and `memory/*.md` prompt injection checks
- dangerous shell payloads in memory files

Full scan coverage:

- deep skill scan
- dependency audit
- session history scanning
- credential and permission checks
- recent tool-call behavior analysis

### 4. Audit Logging

Security events are written to a local append-only audit log:

```text
~/.openclaw/claws-defender/claws-defender-audit.jsonl
```

The log is sanitized by default:

- obvious secrets are redacted
- long strings are truncated
- only necessary metadata and previews are stored

## Available Agent Tools

- `guard_quick_scan`: run a quick security scan
- `guard_full_scan`: run a full security scan
- `guard_status`: inspect the latest scan result
- `guard_explain`: explain a finding by ID

Example prompts:

```text
Run a security scan
Do a full security audit
What did the latest scan find?
Explain finding mem-cmd-reverse-shell:MEMORY.md:12
```

## Installation

This plugin is installed locally from source.

```bash
git clone https://github.com/Ch1nfo/claws-defender /tmp/claws-defender
cd /tmp/claws-defender
npm install
npm run build
openclaw plugins install /tmp/claws-defender
```

## Requirements

- OpenClaw plugin runtime with the current extension system
- Node.js and npm for local build
- OpenClaw >= `2026.3.23-1`

## Project Scope

Claws-Defender is not a full sandbox and not a replacement for OpenClaw's own security model.
It is a runtime-focused guard layer designed to catch obvious dangerous behavior early, reduce persistence risk, and improve visibility through scanning and audit logs.

## License

MIT. See [LICENSE](./LICENSE).
