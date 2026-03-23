/**
 * Config Scanner — checks OpenClaw configuration for dangerous flags.
 *
 * Enumerates 6 high-risk config flags that weaken security posture.
 */

import fs from "node:fs";
import path from "node:path";
import type { DangerousConfigFlag, ScanFinding, ScanResult } from "../types.js";

// ---------------------------------------------------------------------------
// Dangerous configuration flags
// ---------------------------------------------------------------------------

const DANGEROUS_FLAGS: DangerousConfigFlag[] = [
  {
    path: "gateway.controlUi.dangerouslyDisableDeviceAuth",
    dangerousValue: true,
    severity: "critical",
    description:
      "Device authentication is disabled. Any device can access the Control UI without authorization.",
    recommendation: "Remove this flag or set to false. Only use for local debugging.",
  },
  {
    path: "agents.defaults.sandbox.mode",
    dangerousValue: "off",
    severity: "critical",
    description:
      "Agent sandbox is disabled by default. Tools execute with full host privileges.",
    recommendation: 'Set sandbox.mode to "non-main" or "always" for production deployments.',
  },
  {
    path: "hooks.allowRequestSessionKey",
    dangerousValue: true,
    severity: "high",
    description:
      "External webhook callers can specify arbitrary session keys, enabling injection into existing conversations.",
    recommendation: "Disable this flag unless absolutely required. Prefer server-assigned session keys.",
  },
  {
    path: "hooks.allowUnsafeExternalContent",
    dangerousValue: true,
    severity: "critical",
    description:
      "External content safety boundaries are bypassed. All hook payloads are treated as trusted.",
    recommendation: "Never enable this in production. Only use for temporary debugging.",
  },
  {
    path: "gateway.auth.mode",
    dangerousValue: "none",
    severity: "critical",
    description:
      "Gateway authentication is disabled. Anyone with network access can use the gateway.",
    recommendation: "Configure token or password authentication for any non-loopback deployment.",
  },
  {
    path: "tools.fs.workspaceOnly",
    dangerousValue: false,
    severity: "high",
    description:
      "File system tools can access files outside the workspace directory.",
    recommendation: "Set to true to restrict file operations to the workspace.",
  },
];

// ---------------------------------------------------------------------------
// Config value accessor
// ---------------------------------------------------------------------------

function getNestedValue(obj: Record<string, unknown>, dotPath: string): unknown {
  const parts = dotPath.split(".");
  let current: unknown = obj;

  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== "object") {
      return undefined;
    }
    current = (current as Record<string, unknown>)[part];
  }

  return current;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export type ConfigScanOptions = {
  /** Path to openclaw.json config file, or the parsed config object. */
  configPathOrObject: string | Record<string, unknown>;
};

export function scanConfig(options: ConfigScanOptions): ScanResult {
  const startedAt = Date.now();
  const findings: ScanFinding[] = [];

  let config: Record<string, unknown>;

  if (typeof options.configPathOrObject === "string") {
    const configPath = options.configPathOrObject;
    if (!fs.existsSync(configPath)) {
      return {
        scanner: "config-scanner",
        startedAt,
        completedAt: Date.now(),
        findings: [],
        error: `Config file not found: ${configPath}`,
      };
    }
    try {
      const raw = fs.readFileSync(configPath, "utf-8");
      config = JSON.parse(raw) as Record<string, unknown>;
    } catch (err) {
      return {
        scanner: "config-scanner",
        startedAt,
        completedAt: Date.now(),
        findings: [],
        error: `Failed to parse config: ${String(err)}`,
      };
    }
  } else {
    config = options.configPathOrObject;
  }

  for (const flag of DANGEROUS_FLAGS) {
    const value = getNestedValue(config, flag.path);

    // Check if the value matches the dangerous value
    if (value === flag.dangerousValue) {
      findings.push({
        id: `cfg-${flag.path.replace(/\./g, "-")}`,
        scanner: "config-scanner",
        severity: flag.severity,
        title: `Dangerous config: ${flag.path}`,
        description: flag.description,
        recommendation: flag.recommendation,
      });
    }
  }

  return {
    scanner: "config-scanner",
    startedAt,
    completedAt: Date.now(),
    findings,
  };
}

/** Returns the list of all checked flags for documentation/reporting. */
export function getDangerousFlags(): DangerousConfigFlag[] {
  return [...DANGEROUS_FLAGS];
}
