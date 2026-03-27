/**
 * Full Scan — comprehensive security scan, intended for manual trigger or daily cron.
 *
 * Covers everything in quick scan PLUS:
 * 5. Full skills deep scan (all files, all languages)
 * 6. Extension dependency CVE scan (npm audit)
 * 7. Session history DLP scan (API keys, PII)
 * 8. Credential file permission audit
 * 9. Tool call history behavior analysis
 *
 * Target: 1-5 minutes depending on project size
 */

import fs from "node:fs";
import path from "node:path";
import { checkIntegrity } from "../baseline/hash-store.js";
import type { MemorySemanticAnalyzer } from "../llm/memory-semantic-analyzer.js";
import { scanConfig } from "../scanners/config-scanner.js";
import { scanCredentials } from "../scanners/cred-scanner.js";
import { scanDependencies } from "../scanners/dep-scanner.js";
import { scanMemory } from "../scanners/memory-scanner.js";
import { scanSessions } from "../scanners/session-scanner.js";
import { scanSkills } from "../scanners/skill-scanner.js";
import type { ScanReport, ScanResult, ScanSeverity, ToolCallRecord } from "../types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function countBySeverity(results: ScanResult[]): ScanReport["summary"] {
  const summary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const result of results) {
    for (const finding of result.findings) {
      summary.total++;
      summary[finding.severity as ScanSeverity]++;
    }
  }
  return summary;
}

function collectExtensionEntryFiles(extensionsDir: string): string[] {
  const entryFiles: string[] = [];
  if (!fs.existsSync(extensionsDir)) return entryFiles;

  try {
    const dirs = fs.readdirSync(extensionsDir, { withFileTypes: true });
    for (const dir of dirs) {
      if (!dir.isDirectory()) continue;
      const candidates = ["index.ts", "index.js", "src/index.ts", "src/index.js"];
      for (const candidate of candidates) {
        const fullPath = path.join(extensionsDir, dir.name, candidate);
        if (fs.existsSync(fullPath)) {
          entryFiles.push(fullPath);
          break;
        }
      }
    }
  } catch {
    /* skip */
  }

  return entryFiles;
}

async function scanMemorySemantically(params: {
  workspaceDir: string;
  semanticAnalyzer: MemorySemanticAnalyzer;
  maxFiles?: number;
  maxCharsPerFile?: number;
}): Promise<ScanResult> {
  const startedAt = Date.now();
  const findings: ScanResult["findings"] = [];
  const candidates: string[] = [];
  const maxFiles = params.maxFiles ?? 20;
  const maxCharsPerFile = params.maxCharsPerFile ?? 8_000;
  const memoryMdPath = path.join(params.workspaceDir, "MEMORY.md");
  if (fs.existsSync(memoryMdPath)) {
    candidates.push(memoryMdPath);
  }
  const memoryDir = path.join(params.workspaceDir, "memory");
  if (fs.existsSync(memoryDir)) {
    try {
      for (const entry of fs.readdirSync(memoryDir)) {
        if (entry.endsWith(".md")) {
          candidates.push(path.join(memoryDir, entry));
        }
      }
    } catch {
      // ignore
    }
  }

  for (const filePath of candidates.slice(0, maxFiles)) {
    let content = "";
    try {
      content = fs.readFileSync(filePath, "utf-8");
    } catch {
      continue;
    }
    const trimmed = content.trim();
    if (!trimmed) {
      continue;
    }
    const truncated = trimmed.slice(0, maxCharsPerFile);
    const semantic = await params.semanticAnalyzer.analyze({
      content: truncated,
      source: "memory_file_scan",
      filePath,
      workspaceDir: params.workspaceDir,
      ruleFindings: [],
    });
    if (!semantic || semantic.risk === "safe") {
      continue;
    }
    findings.push({
      id: `memory-semantic:${path.basename(filePath)}`,
      scanner: "memory-semantic-scanner",
      severity: semantic.risk === "malicious" ? "high" : "medium",
      title:
        semantic.risk === "malicious"
          ? "Semantic memory risk detected"
          : "Suspicious semantic memory content",
      description: `${path.basename(filePath)} was classified as ${semantic.risk} (${Math.round(
        semantic.confidence * 100,
      )}% confidence). ${semantic.rationale}`,
      file: filePath,
      recommendation:
        semantic.recommendedAction === "block"
          ? "Review and sanitize this memory content before future agent runs load it."
          : "Review this memory content for indirect behavioral manipulation or hidden instructions.",
    });
  }

  return {
    scanner: "memory-semantic-scanner",
    startedAt,
    completedAt: Date.now(),
    findings,
  };
}

// ---------------------------------------------------------------------------
// Tool call behavior analysis
// ---------------------------------------------------------------------------

function analyzeToolCallHistory(recentCalls: ToolCallRecord[]): ScanResult {
  const startedAt = Date.now();
  const findings: ScanResult["findings"] = [];

  if (recentCalls.length === 0) {
    return { scanner: "behavior-analyzer", startedAt, completedAt: Date.now(), findings };
  }

  // Detect rapid file reads (potential enumeration)
  const fileReadCalls = recentCalls.filter(
    (c) => c.toolName === "file_read" || c.toolName === "read_file",
  );
  if (fileReadCalls.length > 20) {
    const uniquePaths = new Set(
      fileReadCalls
        .map((c) => (typeof c.params.path === "string" ? c.params.path : ""))
        .filter(Boolean),
    );
    if (uniquePaths.size > 15) {
      findings.push({
        id: "behavior-rapid-file-reads",
        scanner: "behavior-analyzer",
        severity: "medium",
        title: "Rapid file enumeration detected",
        description: `${fileReadCalls.length} file reads targeting ${uniquePaths.size} unique paths in recent history.`,
        recommendation: "Review agent session to determine if this behavior is expected.",
      });
    }
  }

  // Detect high error rate (potential probing)
  const errorCalls = recentCalls.filter((c) => c.error);
  const errorRate = errorCalls.length / recentCalls.length;
  if (errorRate > 0.5 && errorCalls.length > 5) {
    findings.push({
      id: "behavior-high-error-rate",
      scanner: "behavior-analyzer",
      severity: "medium",
      title: "High tool call error rate",
      description: `${errorCalls.length}/${recentCalls.length} (${(errorRate * 100).toFixed(0)}%) tool calls resulted in errors. May indicate probing.`,
      recommendation: "Review failed tool calls for patterns of boundary testing.",
    });
  }

  // Detect sensitive path access
  const sensitivePathCalls = recentCalls.filter((c) => {
    const p = typeof c.params.path === "string" ? c.params.path : "";
    return /\.(ssh|aws|openclaw\/credentials|gnupg|config\/gcloud)/.test(p);
  });
  if (sensitivePathCalls.length > 0) {
    findings.push({
      id: "behavior-sensitive-path-access",
      scanner: "behavior-analyzer",
      severity: "high",
      title: "Sensitive path access detected",
      description: `${sensitivePathCalls.length} tool calls accessed sensitive paths (SSH keys, cloud credentials, etc.)`,
      recommendation: "Verify that these accesses were explicitly requested by the user.",
    });
  }

  return { scanner: "behavior-analyzer", startedAt, completedAt: Date.now(), findings };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export type FullScanOptions = {
  /** Project root directory. */
  projectRoot: string;
  /** Workspace directory (for MEMORY.md). */
  workspaceDir?: string;
  /** Path to openclaw.json or the config object. */
  config: string | Record<string, unknown>;
  /** Path to store hash baseline. */
  baselineDir: string;
  /** Path to OpenClaw home dir (default: ~/.openclaw). */
  openclawHome?: string;
  /** Recent tool call records for behavior analysis. */
  recentToolCalls?: ToolCallRecord[];
  semanticAnalyzer: MemorySemanticAnalyzer;
};

export async function runFullScan(options: FullScanOptions): Promise<ScanReport> {
  const startedAt = Date.now();
  const results: ScanResult[] = [];

  const openclawHome = options.openclawHome ?? path.join(process.env.HOME ?? "~", ".openclaw");

  // 1. Plugin entry file integrity check (same as quick scan)
  const extensionsDir = path.join(options.projectRoot, "extensions");
  const entryFiles = collectExtensionEntryFiles(extensionsDir);
  if (entryFiles.length > 0) {
    results.push(
      checkIntegrity({
        files: entryFiles,
        baselinePath: path.join(options.baselineDir, "hash-baseline.json"),
        updateBaseline: true,
      }),
    );
  }

  // 2. Dangerous configuration flags
  results.push(scanConfig({ configPathOrObject: options.config }));

  // 3. MEMORY.md check
  const workspaceDir = options.workspaceDir ?? process.cwd();
  results.push(scanMemory({ workspaceDir }));
  results.push(
    await scanMemorySemantically({
      workspaceDir,
      semanticAnalyzer: options.semanticAnalyzer,
    }),
  );

  // 4. Full skills deep scan (ALL files, no day filter)
  const skillsDir = path.join(options.projectRoot, "skills");
  if (fs.existsSync(skillsDir)) {
    results.push(scanSkills({ directory: skillsDir, recentDays: 0 }));
  }

  // Also scan extension source code
  if (fs.existsSync(extensionsDir)) {
    results.push(
      scanSkills({ directory: extensionsDir, recentDays: 0 }),
    );
  }

  // 5. Extension dependency CVE scan
  results.push(scanDependencies({ projectRoot: options.projectRoot }));

  // 6. Session history DLP scan
  const sessionsDir = path.join(openclawHome, "sessions");
  results.push(scanSessions({ sessionsDir }));

  // 7. Credential file permission audit
  const credentialsDir = path.join(openclawHome, "credentials");
  results.push(scanCredentials({ credentialsDir }));

  // 8. Tool call behavior analysis
  if (options.recentToolCalls) {
    results.push(analyzeToolCallHistory(options.recentToolCalls));
  }

  const completedAt = Date.now();
  return {
    mode: "full",
    startedAt,
    completedAt,
    results,
    summary: countBySeverity(results),
  };
}
