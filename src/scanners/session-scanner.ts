/**
 * Session Scanner — scans historical session files for leaked PII and sensitive data.
 *
 * Provides DLP (Data Loss Prevention) capabilities by scanning session transcripts
 * for API keys, credit card numbers, SSNs, and other PII patterns.
 */

import fs from "node:fs";
import path from "node:path";
import type { ScanFinding, ScanResult } from "../types.js";

// ---------------------------------------------------------------------------
// PII / sensitive data patterns
// ---------------------------------------------------------------------------

type PiiRule = {
  id: string;
  title: string;
  pattern: RegExp;
  severity: "critical" | "high" | "medium";
};

const PII_RULES: PiiRule[] = [
  // API keys / tokens
  {
    id: "pii-openai-key",
    title: "OpenAI API key",
    pattern: /sk-[a-zA-Z0-9]{20,}/,
    severity: "critical",
  },
  {
    id: "pii-anthropic-key",
    title: "Anthropic API key",
    pattern: /sk-ant-[a-zA-Z0-9-]{20,}/,
    severity: "critical",
  },
  {
    id: "pii-aws-key",
    title: "AWS access key",
    pattern: /AKIA[0-9A-Z]{16}/,
    severity: "critical",
  },
  {
    id: "pii-github-token",
    title: "GitHub personal access token",
    pattern: /ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,}/,
    severity: "critical",
  },
  {
    id: "pii-generic-secret",
    title: "Generic secret/token pattern",
    pattern: /["']?(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*["'][a-zA-Z0-9+/=_-]{16,}["']/i,
    severity: "high",
  },
  // PII
  {
    id: "pii-credit-card",
    title: "Credit card number",
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/,
    severity: "critical",
  },
  {
    id: "pii-ssn",
    title: "Social Security Number (US)",
    pattern: /\b\d{3}-\d{2}-\d{4}\b/,
    severity: "critical",
  },
  {
    id: "pii-china-id",
    title: "Chinese national ID number",
    pattern: /\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b/,
    severity: "critical",
  },
  {
    id: "pii-email-password-combo",
    title: "Email + password combination",
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}.{0,30}(?:password|passwd|pwd)\s*[:=]\s*\S+/i,
    severity: "critical",
  },
  {
    id: "pii-private-key",
    title: "Private key block",
    pattern: /-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----/,
    severity: "critical",
  },
];

// ---------------------------------------------------------------------------
// Scanner logic
// ---------------------------------------------------------------------------

const MAX_SESSION_FILES = 100;
const MAX_SESSION_SIZE = 2 * 1024 * 1024; // 2 MB per session file

export type SessionScanOptions = {
  /** Directory containing session files (default: ~/.openclaw/sessions/). */
  sessionsDir: string;
  /** Maximum number of session files to scan. */
  maxFiles?: number;
};

export function scanSessions(options: SessionScanOptions): ScanResult {
  const startedAt = Date.now();
  const findings: ScanFinding[] = [];
  const { sessionsDir, maxFiles = MAX_SESSION_FILES } = options;

  if (!fs.existsSync(sessionsDir)) {
    return {
      scanner: "session-scanner",
      startedAt,
      completedAt: Date.now(),
      findings: [],
    };
  }

  let sessionFiles: string[];
  try {
    sessionFiles = fs
      .readdirSync(sessionsDir)
      .filter((f) => f.endsWith(".json") || f.endsWith(".jsonl"))
      .slice(0, maxFiles)
      .map((f) => path.join(sessionsDir, f));
  } catch {
    return {
      scanner: "session-scanner",
      startedAt,
      completedAt: Date.now(),
      findings: [],
      error: "Cannot read sessions directory",
    };
  }

  for (const filePath of sessionFiles) {
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > MAX_SESSION_SIZE) continue;

      const content = fs.readFileSync(filePath, "utf-8");
      const fileName = path.basename(filePath);

      for (const rule of PII_RULES) {
        if (rule.pattern.test(content)) {
          findings.push({
            id: `${rule.id}:${fileName}`,
            scanner: "session-scanner",
            severity: rule.severity,
            title: `${rule.title} found in session`,
            description: `Session file "${fileName}" contains data matching ${rule.title} pattern.`,
            file: filePath,
            recommendation:
              "Review the session file and remove sensitive data. Consider enabling log redaction.",
          });
        }
      }
    } catch {
      // Skip files we cannot read
    }
  }

  return {
    scanner: "session-scanner",
    startedAt,
    completedAt: Date.now(),
    findings,
  };
}
