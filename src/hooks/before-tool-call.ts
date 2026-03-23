/**
 * Before Tool Call Hook — the semantic firewall of claws-defender.
 *
 * Intercepts tool calls before execution and evaluates risk:
 * - High-risk command patterns (reverse shells, data exfiltration)
 * - Memory file write protection (prompt injection prevention)
 * - Tool call sequence anomaly detection
 */

import type { PluginHookBeforeToolCallEvent, PluginHookBeforeToolCallResult, PluginHookToolContext } from "openclaw/plugin-sdk/core";
import type { AuditLog } from "../audit/immutable-log.js";
import { scanContentForInjection } from "../scanners/memory-scanner.js";
import type { ToolCallRecord, GuardDecision } from "../types.js";

// ---------------------------------------------------------------------------
// Risk scoring rules for bash/exec commands
// ---------------------------------------------------------------------------

type CommandRule = {
  pattern: RegExp;
  score: number;
  label: string;
};

const COMMAND_RISK_RULES: CommandRule[] = [
  // Critical: reverse shell patterns
  { pattern: /\/dev\/tcp\//, score: 100, label: "reverse-shell-dev-tcp" },
  { pattern: /nc\s+-[elp]|ncat\s+-/, score: 100, label: "netcat-listener" },
  { pattern: /bash\s+-i\s+>&/, score: 100, label: "bash-interactive-redirect" },
  { pattern: /mkfifo.*nc\s/, score: 100, label: "mkfifo-netcat" },

  // Critical: remote code execution
  { pattern: /curl\s+[^|]*\|\s*(sh|bash|zsh|python|perl|ruby)/, score: 95, label: "curl-pipe-shell" },
  { pattern: /wget\s+[^|]*\|\s*(sh|bash|zsh)/, score: 95, label: "wget-pipe-shell" },

  // High: data exfiltration
  { pattern: /curl\s+.*--data.*(@\/etc\/|@~\/|@\/home)/, score: 80, label: "curl-exfil-file" },
  { pattern: /curl\s+.*-F\s+.*@/, score: 70, label: "curl-upload-file" },
  { pattern: /tar\s+.*\|\s*curl/, score: 80, label: "tar-pipe-curl" },

  // High: credential access
  { pattern: /cat\s+(\/etc\/shadow|\/etc\/passwd|~\/.ssh\/|~\/.aws\/|~\/.openclaw\/credentials)/, score: 85, label: "read-sensitive-file" },
  { pattern: /\.ssh\/authorized_keys/, score: 80, label: "ssh-key-injection" },

  // High: privilege escalation
  { pattern: /chmod\s+u\+s|chmod\s+[4267][0-7]{2}/, score: 75, label: "suid-setgid" },
  { pattern: /crontab\s+-|\/etc\/cron/, score: 70, label: "cron-persistence" },

  // Medium: suspicious operations
  { pattern: /rm\s+-rf\s+\//, score: 60, label: "destructive-rm-root" },
  { pattern: /rm\s+-rf\s+~\//, score: 50, label: "destructive-rm-home" },
  { pattern: /eval\s+\$/, score: 55, label: "shell-eval-variable" },
  { pattern: /base64\s+(-d|--decode)\s*\|/, score: 60, label: "base64-decode-pipe" },

  // Low-medium: environment harvesting
  { pattern: /env\s*\|\s*curl|printenv\s*\|\s*curl/, score: 65, label: "env-harvest-curl" },
  { pattern: /process\.env[\s\S]*fetch/, score: 60, label: "env-harvest-fetch" },
];

const RISK_THRESHOLD_BLOCK = 80;
const RISK_THRESHOLD_WARN = 50;

export function evaluateCommandRisk(command: string): { score: number; matchedRules: string[] } {
  let maxScore = 0;
  const matchedRules: string[] = [];

  for (const rule of COMMAND_RISK_RULES) {
    if (rule.pattern.test(command)) {
      maxScore = Math.max(maxScore, rule.score);
      matchedRules.push(rule.label);
    }
  }

  return { score: maxScore, matchedRules };
}

// ---------------------------------------------------------------------------
// Memory path detection
// ---------------------------------------------------------------------------

function isMemoryPath(filePath: string): boolean {
  const normalized = filePath.toLowerCase();
  return normalized.endsWith("/memory.md") || normalized.includes("/memory/");
}

// ---------------------------------------------------------------------------
// Exfiltration pattern detection (tool call sequence analysis)
// ---------------------------------------------------------------------------

const EXFIL_WINDOW_MS = 60_000; // 1 minute window

function isExfiltrationPattern(recentCalls: ToolCallRecord[]): boolean {
  if (recentCalls.length < 2) return false;

  const hasFileRead = recentCalls.some(
    (c) => c.toolName === "file_read" || c.toolName === "read_file"
  );
  const hasNetworkEgress = recentCalls.some(
    (c) =>
      c.toolName === "bash_tool" &&
      typeof c.params.command === "string" &&
      /curl|wget|fetch|http/.test(c.params.command)
  );

  return hasFileRead && hasNetworkEgress;
}

// ---------------------------------------------------------------------------
// Hook handler factory
// ---------------------------------------------------------------------------

export type BeforeToolCallHandlerDeps = {
  auditLog: AuditLog;
  recentToolCalls: ToolCallRecord[];
};

export function createBeforeToolCallHandler(deps: BeforeToolCallHandlerDeps) {
  return async (
    event: PluginHookBeforeToolCallEvent,
    ctx: PluginHookToolContext,
  ): Promise<PluginHookBeforeToolCallResult | void> => {
    const { toolName, params } = event;
    const { auditLog, recentToolCalls } = deps;

    // Rule 1: High-risk command detection for bash/exec tools
    if (toolName === "bash_tool" || toolName === "exec" || toolName === "shell") {
      const command = typeof params.command === "string" ? params.command : "";
      if (command.length > 0) {
        const risk = evaluateCommandRisk(command);

        if (risk.score >= RISK_THRESHOLD_BLOCK) {
          const reason = `High-risk command blocked (score: ${risk.score}, rules: ${risk.matchedRules.join(", ")})`;
          auditLog.logToolBlock({
            toolName,
            reason,
            params,
            sessionKey: ctx.sessionKey,
          });
          return { block: true, blockReason: reason };
        }

        if (risk.score >= RISK_THRESHOLD_WARN) {
          auditLog.logAlert({
            timestamp: Date.now(),
            level: "warn",
            source: "before-tool-call",
            toolName,
            sessionKey: ctx.sessionKey,
            message: `Suspicious command detected (score: ${risk.score}, rules: ${risk.matchedRules.join(", ")})`,
            details: { command: command.slice(0, 200) },
          });
        }
      }
    }

    // Rule 2: Memory file write protection
    if (toolName === "file_write" || toolName === "write_file") {
      const filePath = typeof params.path === "string" ? params.path : (typeof params.file_path === "string" ? params.file_path : "");
      if (isMemoryPath(filePath)) {
        const content = typeof params.content === "string" ? params.content : "";
        if (content.length > 0) {
          const injectionFindings = scanContentForInjection(content);
          if (injectionFindings.length > 0) {
            const criticalCount = injectionFindings.filter((f) => f.severity === "critical").length;
            auditLog.logAlert({
              timestamp: Date.now(),
              level: criticalCount > 0 ? "critical" : "warn",
              source: "before-tool-call",
              toolName,
              sessionKey: ctx.sessionKey,
              message: `Prompt injection patterns detected in memory write (${injectionFindings.length} findings, ${criticalCount} critical)`,
              details: {
                filePath,
                findings: injectionFindings.map((f) => f.title),
              },
            });

            // Block if critical injection patterns are found
            if (criticalCount > 0) {
              const reason = `Memory write blocked: ${criticalCount} critical prompt injection patterns detected`;
              auditLog.logToolBlock({ toolName, reason, params, sessionKey: ctx.sessionKey });
              return { block: true, blockReason: reason };
            }
          }
        }
      }
    }

    // Rule 3: Tool call sequence anomaly detection
    const now = Date.now();
    const windowCalls = recentToolCalls.filter((c) => now - c.timestamp < EXFIL_WINDOW_MS);
    if (isExfiltrationPattern(windowCalls)) {
      const reason = "Suspected data exfiltration: file read followed by network egress within 60s window";
      auditLog.logAlert({
        timestamp: now,
        level: "critical",
        source: "before-tool-call",
        toolName,
        sessionKey: ctx.sessionKey,
        message: reason,
        details: { recentToolNames: windowCalls.map((c) => c.toolName) },
      });
      return { block: true, blockReason: reason };
    }

    return undefined; // Allow
  };
}
