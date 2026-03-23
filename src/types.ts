/**
 * Claws-Defender shared types.
 */

export type ScanSeverity = "critical" | "high" | "medium" | "low" | "info";

export type ScanFinding = {
  id: string;
  scanner: string;
  severity: ScanSeverity;
  title: string;
  description: string;
  file?: string;
  line?: number;
  recommendation?: string;
};

export type ScanResult = {
  scanner: string;
  startedAt: number;
  completedAt: number;
  findings: ScanFinding[];
  error?: string;
};

export type ScanReport = {
  mode: "quick" | "full";
  startedAt: number;
  completedAt: number;
  results: ScanResult[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
};

export type AlertLevel = "critical" | "warn" | "info";

export type GuardAlert = {
  timestamp: number;
  level: AlertLevel;
  source: string;
  toolName?: string;
  sessionKey?: string;
  message: string;
  details?: Record<string, unknown>;
};

export type GuardDecision = {
  action: "allow" | "block" | "warn";
  reason?: string;
};

/** Tool call record for behavior baseline tracking. */
export type ToolCallRecord = {
  timestamp: number;
  toolName: string;
  params: Record<string, unknown>;
  sessionKey?: string;
  runId?: string;
  durationMs?: number;
  error?: string;
};

/** Dangerous config flag definition */
export type DangerousConfigFlag = {
  path: string;
  dangerousValue: unknown;
  severity: ScanSeverity;
  description: string;
  recommendation: string;
};
