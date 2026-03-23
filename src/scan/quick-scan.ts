/**
 * Quick Scan — fast security scan designed to run on Gateway startup.
 *
 * Covers:
 * 1. Plugin entry file integrity (hash baseline comparison)
 * 2. Dangerous configuration flag enumeration
 * 3. Recently modified Skills code scan (last 7 days, JS/TS/Python/Shell)
 * 4. Current MEMORY.md prompt injection check
 *
 * Target: complete in < 10 seconds
 */

import fs from "node:fs";
import path from "node:path";
import { checkIntegrity } from "../baseline/hash-store.js";
import { scanConfig } from "../scanners/config-scanner.js";
import { scanMemory } from "../scanners/memory-scanner.js";
import { scanSkills } from "../scanners/skill-scanner.js";
import type { ScanReport, ScanResult, ScanSeverity } from "../types.js";

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

      // Check common entry points
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
    // Cannot read extensions dir
  }

  return entryFiles;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export type QuickScanOptions = {
  /** Project root directory. */
  projectRoot: string;
  /** Workspace directory (for MEMORY.md). */
  workspaceDir?: string;
  /** Path to openclaw.json or the config object. */
  config: string | Record<string, unknown>;
  /** Path to store hash baseline. Default: ~/.openclaw/claws-defender/ */
  baselineDir: string;
};

export function runQuickScan(options: QuickScanOptions): ScanReport {
  const startedAt = Date.now();
  const results: ScanResult[] = [];

  // 1. Plugin entry file integrity check
  const extensionsDir = path.join(options.projectRoot, "extensions");
  const entryFiles = collectExtensionEntryFiles(extensionsDir);
  if (entryFiles.length > 0) {
    const integrityResult = checkIntegrity({
      files: entryFiles,
      baselinePath: path.join(options.baselineDir, "hash-baseline.json"),
      updateBaseline: true,
    });
    results.push(integrityResult);
  }

  // 2. Dangerous configuration flags
  const configResult = scanConfig({ configPathOrObject: options.config });
  results.push(configResult);

  // 3. Recently modified Skills (last 7 days)
  const skillsDir = path.join(options.projectRoot, "skills");
  if (fs.existsSync(skillsDir)) {
    const skillResult = scanSkills({
      directory: skillsDir,
      recentDays: 7,
    });
    results.push(skillResult);
  }

  // 4. Current MEMORY.md check
  const workspaceDir = options.workspaceDir ?? process.cwd();
  const memoryResult = scanMemory({ workspaceDir });
  results.push(memoryResult);

  const completedAt = Date.now();
  return {
    mode: "quick",
    startedAt,
    completedAt,
    results,
    summary: countBySeverity(results),
  };
}
