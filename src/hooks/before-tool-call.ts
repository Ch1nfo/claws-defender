/**
 * Before Tool Call Hook — the semantic firewall of claws-defender.
 *
 * Intercepts tool calls before execution and evaluates risk:
 * - High-risk command patterns (reverse shells, data exfiltration)
 * - Memory file write protection (prompt injection prevention)
 * - Tool call sequence anomaly detection
 */

import type { AuditLog } from "../audit/immutable-log.js";
import type { MemorySemanticAnalyzer } from "../llm/memory-semantic-analyzer.js";
import { evaluateCommandRules } from "../security/command-rules.js";
import { analyzeMemoryWrite } from "../scanners/memory-scanner.js";
import type {
  DefenderBeforeToolCallEvent,
  DefenderBeforeToolCallResult,
  DefenderToolContext,
  ToolCallRecord,
} from "../types.js";

// ---------------------------------------------------------------------------
// Risk scoring rules for bash/exec commands
// ---------------------------------------------------------------------------

const RISK_THRESHOLD_BLOCK = 80;
const RISK_THRESHOLD_WARN = 50;

export function evaluateCommandRisk(command: string): { score: number; matchedRules: string[] } {
  const risk = evaluateCommandRules(command, "execution");
  return { score: risk.score, matchedRules: risk.matchedRules.map((rule) => rule.label) };
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
  semanticAnalyzer: MemorySemanticAnalyzer;
  logger: {
    warn: (msg: string) => void;
  };
  resolveWorkspaceDir: () => string;
};

export function createBeforeToolCallHandler(deps: BeforeToolCallHandlerDeps) {
  return async (
    event: DefenderBeforeToolCallEvent,
    ctx: DefenderToolContext,
  ): Promise<DefenderBeforeToolCallResult | void> => {
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
      const filePath =
        typeof params.path === "string"
          ? params.path
          : (typeof params.file_path === "string" ? params.file_path : "");
      if (isMemoryPath(filePath)) {
        const content = typeof params.content === "string" ? params.content : "";
        if (content.length > 0) {
          const scanResult = analyzeMemoryWrite(content);
          const injectionFindings = scanResult.findings;
          if (injectionFindings.length > 0) {
            const criticalCount = injectionFindings.filter((f) => f.severity === "critical").length;
            const shellCount = injectionFindings.filter((f) =>
              f.id.startsWith("mem-cmd-")
            ).length;
            auditLog.logAlert({
              timestamp: Date.now(),
              level: criticalCount > 0 ? "critical" : "warn",
              source: "before-tool-call",
              toolName,
              sessionKey: ctx.sessionKey,
              message: `Suspicious memory write detected (${injectionFindings.length} findings, ${criticalCount} critical, ${shellCount} shell command matches)`,
              details: {
                filePath,
                findings: injectionFindings.map((f) => f.title),
              },
            });

            if (scanResult.shouldBlockWrite) {
              const reason = `Memory write blocked: dangerous shell command detected in memory content`;
              auditLog.logToolBlock({ toolName, reason, params, sessionKey: ctx.sessionKey });
              return { block: true, blockReason: reason };
            }
          }

          const semantic = await deps.semanticAnalyzer.analyze({
            content,
            source: "memory_write",
            filePath,
            workspaceDir: deps.resolveWorkspaceDir(),
            ruleFindings: injectionFindings,
          });

          auditLog.logSemanticMemoryAnalysis({
            source: "memory_write",
            filePath,
            sessionKey: ctx.sessionKey,
            risk: semantic?.risk,
            confidence: semantic?.confidence,
            recommendedAction: semantic?.recommendedAction,
            categories: semantic?.categories,
            blocked:
              semantic?.risk === "malicious" &&
              semantic.recommendedAction === "block" &&
              semantic.confidence >= 0.85,
          });

          if (
            semantic?.risk === "malicious" &&
            semantic.recommendedAction === "block" &&
            semantic.confidence >= 0.85
          ) {
            const reason = `Memory write blocked: semantic analysis classified content as malicious (${semantic.rationale})`;
            auditLog.logToolBlock({ toolName, reason, params, sessionKey: ctx.sessionKey });
            return { block: true, blockReason: reason };
          }

          if (semantic?.risk === "suspicious" || semantic?.risk === "malicious") {
            auditLog.logAlert({
              timestamp: Date.now(),
              level: semantic.risk === "malicious" ? "critical" : "warn",
              source: "before-tool-call",
              toolName,
              sessionKey: ctx.sessionKey,
              message: `Memory write semantic analysis flagged content as ${semantic.risk} (${Math.round(
                semantic.confidence * 100,
              )}% confidence)`,
              details: {
                filePath,
                categories: semantic.categories,
                rationale: semantic.rationale,
                evidenceSpans: semantic.evidenceSpans,
              },
            });
          } else if (!semantic) {
            deps.logger.warn("[claws-defender] Memory semantic analysis unavailable; allowing write.");
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
