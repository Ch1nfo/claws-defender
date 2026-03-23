/**
 * Credential Scanner — audits file permissions on credential storage.
 *
 * Checks that credential files under ~/.openclaw/credentials/ have
 * restrictive permissions (0600) to prevent unauthorized access by
 * other processes on the same host.
 */

import fs from "node:fs";
import path from "node:path";
import type { ScanFinding, ScanResult } from "../types.js";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export type CredScanOptions = {
  /** Path to credentials directory (default: ~/.openclaw/credentials/). */
  credentialsDir: string;
};

export function scanCredentials(options: CredScanOptions): ScanResult {
  const startedAt = Date.now();
  const findings: ScanFinding[] = [];
  const { credentialsDir } = options;

  if (!fs.existsSync(credentialsDir)) {
    return {
      scanner: "cred-scanner",
      startedAt,
      completedAt: Date.now(),
      findings: [],
    };
  }

  // On Windows, POSIX permissions are not meaningful
  if (process.platform === "win32") {
    return {
      scanner: "cred-scanner",
      startedAt,
      completedAt: Date.now(),
      findings: [
        {
          id: "cred-windows-skip",
          scanner: "cred-scanner",
          severity: "info",
          title: "Credential permission check skipped on Windows",
          description: "POSIX file permissions are not applicable on Windows.",
          recommendation: "Verify Windows ACLs manually for credential files.",
        },
      ],
    };
  }

  // Check the directory itself
  try {
    const dirStat = fs.statSync(credentialsDir);
    const dirMode = dirStat.mode & 0o777;
    if ((dirMode & 0o077) !== 0) {
      findings.push({
        id: "cred-dir-permissions",
        scanner: "cred-scanner",
        severity: "high",
        title: "Credentials directory has loose permissions",
        description: `${credentialsDir} has mode ${dirMode.toString(8)} (expected 0700 or stricter).`,
        file: credentialsDir,
        recommendation: `Run: chmod 700 "${credentialsDir}"`,
      });
    }
  } catch {
    // Cannot stat directory
  }

  // Check individual files
  try {
    const entries = fs.readdirSync(credentialsDir);
    for (const entry of entries) {
      const filePath = path.join(credentialsDir, entry);
      try {
        const stat = fs.statSync(filePath);
        if (!stat.isFile()) continue;

        const mode = stat.mode & 0o777;
        // Files should be 0600 (owner read/write only)
        if ((mode & 0o077) !== 0) {
          findings.push({
            id: `cred-file-${entry}`,
            scanner: "cred-scanner",
            severity: "high",
            title: `Credential file has loose permissions: ${entry}`,
            description: `${filePath} has mode ${mode.toString(8)} — group/other can read. Expected 0600.`,
            file: filePath,
            recommendation: `Run: chmod 600 "${filePath}"`,
          });
        }
      } catch {
        // Skip files we cannot stat
      }
    }
  } catch {
    // Cannot read directory
  }

  return {
    scanner: "cred-scanner",
    startedAt,
    completedAt: Date.now(),
    findings,
  };
}
