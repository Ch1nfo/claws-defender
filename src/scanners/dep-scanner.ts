/**
 * Dependency Scanner — wraps npm audit for extension plugin CVE scanning.
 */

import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type { ScanFinding, ScanResult, ScanSeverity } from "../types.js";

// ---------------------------------------------------------------------------
// npm audit JSON shape (subset we care about)
// ---------------------------------------------------------------------------

type NpmAuditVulnerability = {
  name: string;
  severity: string;
  via: Array<string | { title?: string; url?: string; severity?: string }>;
  range?: string;
  fixAvailable?: boolean | { name: string; version: string };
};

type NpmAuditReport = {
  vulnerabilities?: Record<string, NpmAuditVulnerability>;
  metadata?: {
    vulnerabilities?: Record<string, number>;
    totalDependencies?: number;
  };
};

function mapSeverity(npmSeverity: string): ScanSeverity {
  switch (npmSeverity.toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "moderate":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export type DepScanOptions = {
  /** Root directory of the project (containing extensions/). */
  projectRoot: string;
  /** Specific extension directories to scan. If empty, scans all. */
  extensionDirs?: string[];
};

export function scanDependencies(options: DepScanOptions): ScanResult {
  const startedAt = Date.now();
  const findings: ScanFinding[] = [];
  const { projectRoot } = options;

  const extensionsRoot = path.join(projectRoot, "extensions");
  if (!fs.existsSync(extensionsRoot)) {
    return {
      scanner: "dep-scanner",
      startedAt,
      completedAt: Date.now(),
      findings: [],
      error: "Extensions directory not found",
    };
  }

  // Determine which extension dirs to scan
  let dirs: string[];
  if (options.extensionDirs && options.extensionDirs.length > 0) {
    dirs = options.extensionDirs;
  } else {
    try {
      dirs = fs
        .readdirSync(extensionsRoot, { withFileTypes: true })
        .filter((d) => d.isDirectory())
        .map((d) => path.join(extensionsRoot, d.name));
    } catch {
      return {
        scanner: "dep-scanner",
        startedAt,
        completedAt: Date.now(),
        findings: [],
        error: "Cannot read extensions directory",
      };
    }
  }

  for (const dir of dirs) {
    const pkgJsonPath = path.join(dir, "package.json");
    const nodeModulesPath = path.join(dir, "node_modules");

    // Only audit extensions that have their own node_modules
    if (!fs.existsSync(pkgJsonPath) || !fs.existsSync(nodeModulesPath)) continue;

    const extName = path.basename(dir);

    try {
      // npm audit --json exits non-zero when vulnerabilities are found
      const output = execSync("npm audit --json 2>/dev/null", {
        cwd: dir,
        encoding: "utf-8",
        timeout: 30_000,
        stdio: ["pipe", "pipe", "pipe"],
      });

      const report = JSON.parse(output) as NpmAuditReport;
      if (report.vulnerabilities) {
        for (const [name, vuln] of Object.entries(report.vulnerabilities)) {
          const viaDetails = vuln.via
            .map((v) => (typeof v === "string" ? v : v.title ?? v.url ?? "unknown"))
            .join(", ");

          findings.push({
            id: `dep-${extName}-${name}`,
            scanner: "dep-scanner",
            severity: mapSeverity(vuln.severity),
            title: `Vulnerable dependency: ${name} (${vuln.severity})`,
            description: `Extension "${extName}" uses ${name} with known vulnerability: ${viaDetails}`,
            file: pkgJsonPath,
            recommendation: vuln.fixAvailable
              ? `Run \`npm audit fix\` in ${dir}`
              : `Update or replace ${name} manually.`,
          });
        }
      }
    } catch (err) {
      // npm audit returns exit code 1 when vulnerabilities found — try parsing stdout
      if (err && typeof err === "object" && "stdout" in err) {
        try {
          const report = JSON.parse((err as { stdout: string }).stdout) as NpmAuditReport;
          if (report.vulnerabilities) {
            for (const [name, vuln] of Object.entries(report.vulnerabilities)) {
              findings.push({
                id: `dep-${extName}-${name}`,
                scanner: "dep-scanner",
                severity: mapSeverity(vuln.severity),
                title: `Vulnerable dependency: ${name} (${vuln.severity})`,
                description: `Extension "${extName}" uses ${name} with known vulnerability.`,
                file: pkgJsonPath,
                recommendation: vuln.fixAvailable
                  ? `Run \`npm audit fix\` in ${dir}`
                  : `Update or replace ${name} manually.`,
              });
            }
          }
        } catch {
          // Cannot parse audit output, skip this extension
        }
      }
    }
  }

  return {
    scanner: "dep-scanner",
    startedAt,
    completedAt: Date.now(),
    findings,
  };
}
