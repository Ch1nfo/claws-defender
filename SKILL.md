---
name: claws-defender
description: Agent OS runtime security defender — provides security scanning and tool call interception
---

# Claws-Defender

You are connected to the Claws-Defender security plugin, which provides runtime security protection for the OpenClaw Agent OS.

## Available Tools

### guard_quick_scan
Execute a quick security scan (< 10 seconds). Checks:
- Plugin entry file integrity (hash baseline comparison)
- Dangerous configuration flags (6 high-risk settings)
- Recently modified skill code (last 7 days, supports JS/TS/Python/Shell)
- MEMORY.md prompt injection patterns

**Usage**: Call this tool with no arguments to run a quick scan.

**Returns**: A JSON report with scan findings, each containing severity (critical/high/medium/low/info), title, description, and recommendation.

### guard_full_scan
Execute a comprehensive security scan (1-5 minutes). Includes everything in quick scan PLUS:
- Full skill code deep scan (all files, all languages)
- Extension dependency CVE scan (npm audit)
- Session history DLP scan (API keys, PII detection)
- Credential file permission audit
- Tool call behavior anomaly analysis

**Usage**: Call this tool with no arguments. This may take several minutes.

**Returns**: A detailed JSON report with all findings.

### guard_status
View the results of the most recent scan without re-running.

**Usage**: Call this tool to check current security status.

**Returns**: Summary of last scan results, or "No scan has been run yet" if no previous scan exists.

### guard_explain
Get a detailed explanation of a specific security finding.

**Usage**: Call with `finding_id` parameter set to the ID of the finding you want explained.

**Returns**: Detailed description, impact assessment, and remediation steps.

## Automatic Protection

Claws-Defender automatically:
- **Intercepts dangerous tool calls** before execution (reverse shells, data exfiltration, credential theft)
- **Scans inbound messages** for prompt injection patterns
- **Protects MEMORY.md** from persistent prompt injection writes
- **Logs all security events** to an immutable audit log

## Example Queries

- "Run a security scan" → triggers guard_quick_scan
- "Do a full security audit" → triggers guard_full_scan
- "Are there any security issues?" → triggers guard_status
- "Explain finding cfg-gateway-auth-mode" → triggers guard_explain
