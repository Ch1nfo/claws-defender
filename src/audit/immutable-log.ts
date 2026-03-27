/**
 * Immutable Audit Log — append-only JSONL logging for security events.
 *
 * All guard decisions, alerts, and scan results are persisted here.
 * The log is append-only by design: no deletion or modification APIs.
 */

import fs from "node:fs";
import path from "node:path";
import type { GuardAlert, ScanReport } from "../types.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type AuditEntry = {
  timestamp: number;
  type:
    | "alert"
    | "scan_report"
    | "tool_block"
    | "injection_detected"
    | "semantic_memory_analysis"
    | "startup";
  data: GuardAlert | ScanReport | Record<string, unknown>;
};

const MAX_STRING_LENGTH = 160;
const REDACTED = "[redacted]";

function sanitizeKey(key: string): string {
  return key.toLowerCase();
}

function shouldRedactKey(key: string): boolean {
  const normalized = sanitizeKey(key);
  return [
    "token",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "cookie",
    "credential",
    "private_key",
    "access_key",
    "refresh_token",
    "session_key",
  ].some((pattern) => normalized.includes(pattern));
}

function redactSecrets(input: string): string {
  return input
    .replace(/sk-ant-[a-zA-Z0-9-]{12,}/g, REDACTED)
    .replace(/sk-[a-zA-Z0-9]{12,}/g, REDACTED)
    .replace(/AKIA[0-9A-Z]{16}/g, REDACTED)
    .replace(/ghp_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{20,}/g, REDACTED)
    .replace(/-----BEGIN[\s\S]{0,80}?PRIVATE KEY-----/g, REDACTED);
}

function sanitizeString(value: string): string {
  const redacted = redactSecrets(value);
  if (redacted.length <= MAX_STRING_LENGTH) return redacted;
  return `${redacted.slice(0, MAX_STRING_LENGTH)}...[truncated]`;
}

function sanitizeValue(value: unknown, key?: string): unknown {
  if (key && shouldRedactKey(key)) return REDACTED;

  if (typeof value === "string") {
    return sanitizeString(value);
  }

  if (Array.isArray(value)) {
    return value.slice(0, 20).map((item) => sanitizeValue(item));
  }

  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const sanitized: Record<string, unknown> = {};

    for (const [entryKey, entryValue] of Object.entries(record)) {
      sanitized[entryKey] = sanitizeValue(entryValue, entryKey);
    }

    return sanitized;
  }

  return value;
}

// ---------------------------------------------------------------------------
// Logger class
// ---------------------------------------------------------------------------

export class AuditLog {
  private readonly logPath: string;

  constructor(logDir: string, filename = "claws-defender-audit.jsonl") {
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
    this.logPath = path.join(logDir, filename);
  }

  /** Append an entry to the audit log. */
  append(entry: AuditEntry): void {
    const line = JSON.stringify(entry) + "\n";
    try {
      fs.appendFileSync(this.logPath, line, "utf-8");
    } catch {
      // Fail silently — audit logging should never crash the plugin
    }
  }

  /** Log a guard alert. */
  logAlert(alert: GuardAlert): void {
    this.append({
      timestamp: Date.now(),
      type: "alert",
      data: sanitizeValue(alert) as GuardAlert,
    });
  }

  /** Log a tool call block decision. */
  logToolBlock(details: {
    toolName: string;
    reason: string;
    params: Record<string, unknown>;
    sessionKey?: string;
  }): void {
    this.append({
      timestamp: Date.now(),
      type: "tool_block",
      data: {
        toolName: details.toolName,
        reason: sanitizeString(details.reason),
        sessionKey: details.sessionKey ? REDACTED : undefined,
        params: sanitizeValue(details.params),
      },
    });
  }

  /** Log a prompt injection detection. */
  logInjectionDetected(details: {
    source: string;
    content: string;
    findings: number;
    sessionKey?: string;
    channelId?: string;
  }): void {
    this.append({
      timestamp: Date.now(),
      type: "injection_detected",
      data: {
        source: details.source,
        findings: details.findings,
        sessionKey: details.sessionKey ? REDACTED : undefined,
        channelId: details.channelId,
        contentPreview: sanitizeString(details.content),
      },
    });
  }

  /** Log semantic memory analysis decisions. */
  logSemanticMemoryAnalysis(details: Record<string, unknown>): void {
    this.append({
      timestamp: Date.now(),
      type: "semantic_memory_analysis",
      data: sanitizeValue(details) as Record<string, unknown>,
    });
  }

  /** Log a scan report. */
  logScanReport(report: ScanReport): void {
    this.append({
      timestamp: Date.now(),
      type: "scan_report",
      data: report,
    });
  }

  /** Log startup event. */
  logStartup(details: { port?: number; timestamp: number }): void {
    this.append({
      timestamp: Date.now(),
      type: "startup",
      data: details,
    });
  }

  /** Read recent entries (tail of log). */
  readRecent(maxEntries = 50): AuditEntry[] {
    if (!fs.existsSync(this.logPath)) return [];

    try {
      const content = fs.readFileSync(this.logPath, "utf-8");
      const lines = content.trim().split("\n").filter(Boolean);
      const recent = lines.slice(-maxEntries);

      return recent
        .map((line) => {
          try {
            return JSON.parse(line) as AuditEntry;
          } catch {
            return null;
          }
        })
        .filter((e): e is AuditEntry => e !== null);
    } catch {
      return [];
    }
  }

  /** Get the log file path (for diagnostics). */
  getLogPath(): string {
    return this.logPath;
  }
}
