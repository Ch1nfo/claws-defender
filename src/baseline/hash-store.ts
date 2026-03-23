/**
 * Hash Store — JSON-backed hash baseline for file integrity verification.
 *
 * On first scan, records SHA-256 hashes of critical files (plugin entry points).
 * On subsequent scans, compares current hashes to detect silent code tampering.
 */

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { ScanFinding, ScanResult } from "../types.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type HashBaseline = {
  version: 1;
  updatedAt: number;
  entries: Record<string, { hash: string; recordedAt: number; size: number }>;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function computeFileHash(filePath: string): string | null {
  try {
    const content = fs.readFileSync(filePath);
    return createHash("sha256").update(content).digest("hex");
  } catch {
    return null;
  }
}

function loadBaseline(baselinePath: string): HashBaseline {
  if (!fs.existsSync(baselinePath)) {
    return { version: 1, updatedAt: 0, entries: {} };
  }
  try {
    const raw = fs.readFileSync(baselinePath, "utf-8");
    return JSON.parse(raw) as HashBaseline;
  } catch {
    return { version: 1, updatedAt: 0, entries: {} };
  }
}

function saveBaseline(baselinePath: string, baseline: HashBaseline): void {
  const dir = path.dirname(baselinePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(baselinePath, JSON.stringify(baseline, null, 2), "utf-8");
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export type IntegrityCheckOptions = {
  /** Files to check integrity of. */
  files: string[];
  /** Path to the baseline JSON file. */
  baselinePath: string;
  /** If true, update the baseline with current hashes for files that have no entry. */
  updateBaseline?: boolean;
};

/**
 * Check file integrity against stored hash baseline.
 *
 * - Files with no baseline entry: recorded (if updateBaseline=true) or reported as "new"
 * - Files whose hash changed: reported as integrity violations
 * - Files that no longer exist: reported as missing
 */
export function checkIntegrity(options: IntegrityCheckOptions): ScanResult {
  const startedAt = Date.now();
  const findings: ScanFinding[] = [];
  const { files, baselinePath, updateBaseline = true } = options;

  const baseline = loadBaseline(baselinePath);
  let baselineModified = false;

  for (const filePath of files) {
    const normalizedPath = path.resolve(filePath);
    const hash = computeFileHash(normalizedPath);

    if (hash === null) {
      // File doesn't exist or can't be read
      if (baseline.entries[normalizedPath]) {
        findings.push({
          id: `integrity-missing:${path.basename(filePath)}`,
          scanner: "integrity-checker",
          severity: "high",
          title: `Baselined file is missing: ${path.basename(filePath)}`,
          description: `${normalizedPath} was in the hash baseline but no longer exists. It may have been deleted.`,
          file: normalizedPath,
          recommendation: "Investigate why a previously known file was removed.",
        });
      }
      continue;
    }

    const entry = baseline.entries[normalizedPath];

    if (!entry) {
      // New file — record it
      if (updateBaseline) {
        const stat = fs.statSync(normalizedPath);
        baseline.entries[normalizedPath] = {
          hash,
          recordedAt: Date.now(),
          size: stat.size,
        };
        baselineModified = true;
      }
      findings.push({
        id: `integrity-new:${path.basename(filePath)}`,
        scanner: "integrity-checker",
        severity: "info",
        title: `New file added to baseline: ${path.basename(filePath)}`,
        description: `${normalizedPath} has been recorded in the integrity baseline.`,
        file: normalizedPath,
        recommendation: "No action needed. File hash recorded for future verification.",
      });
    } else if (entry.hash !== hash) {
      // Hash mismatch — integrity violation!
      findings.push({
        id: `integrity-changed:${path.basename(filePath)}`,
        scanner: "integrity-checker",
        severity: "critical",
        title: `File integrity violation: ${path.basename(filePath)}`,
        description: `${normalizedPath} has been modified since the baseline was recorded. Expected hash: ${entry.hash.slice(0, 16)}..., current hash: ${hash.slice(0, 16)}...`,
        file: normalizedPath,
        recommendation:
          "Investigate the modification. If intentional (e.g., plugin update), re-run the baseline update.",
      });
    }
    // else: hash matches, file is intact
  }

  if (baselineModified) {
    baseline.updatedAt = Date.now();
    saveBaseline(baselinePath, baseline);
  }

  return {
    scanner: "integrity-checker",
    startedAt,
    completedAt: Date.now(),
    findings,
  };
}

/**
 * Re-record the baseline for all specified files.
 * Called after intentional updates (e.g., plugin upgrades).
 */
export function updateBaselineForFiles(files: string[], baselinePath: string): number {
  const baseline = loadBaseline(baselinePath);
  let count = 0;

  for (const filePath of files) {
    const normalizedPath = path.resolve(filePath);
    const hash = computeFileHash(normalizedPath);
    if (hash === null) continue;

    const stat = fs.statSync(normalizedPath);
    baseline.entries[normalizedPath] = {
      hash,
      recordedAt: Date.now(),
      size: stat.size,
    };
    count++;
  }

  baseline.updatedAt = Date.now();
  saveBaseline(baselinePath, baseline);
  return count;
}
