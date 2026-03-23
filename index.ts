/**
 * Claws-Defender — Agent OS Runtime Security Plugin
 *
 * A comprehensive security extension for OpenClaw that provides:
 * - Tool call interception (semantic firewall via before_tool_call hook)
 * - Inbound message scanning (prompt injection detection via message_received hook)
 * - Behavior baseline tracking (via after_tool_call hook)
 * - Dual-mode security scanning (quick scan + full scan)
 * - Agent-callable security tools (guard_quick_scan, guard_full_scan, guard_status, guard_explain)
 * - Immutable audit logging
 */

import path from "node:path";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { emptyPluginConfigSchema } from "openclaw/plugin-sdk/core";
import { AuditLog } from "./src/audit/immutable-log.js";
import { createAfterToolCallHandler } from "./src/hooks/after-tool-call.js";
import { createBeforeToolCallHandler } from "./src/hooks/before-tool-call.js";
import { createOnMessageHandler } from "./src/hooks/on-message.js";
import { runFullScan } from "./src/scan/full-scan.js";
import { runQuickScan } from "./src/scan/quick-scan.js";
import type { ScanFinding, ScanReport, ToolCallRecord } from "./src/types.js";

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

const recentToolCalls: ToolCallRecord[] = [];
let lastScanReport: ScanReport | null = null;

// ---------------------------------------------------------------------------
// Plugin definition
// ---------------------------------------------------------------------------

const clawsDefenderPlugin = {
  id: "claws-defender",
  name: "Claws-Defender",
  description: "Agent OS runtime security defender — tool call interception, prompt injection scanning, and dual-mode security scanning",
  configSchema: emptyPluginConfigSchema(),

  register(api: OpenClawPluginApi) {
    const openclawHome = path.join(process.env.HOME ?? "~", ".openclaw");
    const baselineDir = path.join(openclawHome, "claws-defender");
    const auditLog = new AuditLog(baselineDir);

    // -------------------------------------------------------------------
    // Register hooks
    // -------------------------------------------------------------------

    // 1. before_tool_call — semantic firewall (high priority to run first)
    const beforeToolCallHandler = createBeforeToolCallHandler({ auditLog, recentToolCalls });
    api.on("before_tool_call", beforeToolCallHandler, { priority: 100 });

    // 2. after_tool_call — behavior logging
    const afterToolCallHandler = createAfterToolCallHandler({ recentToolCalls });
    api.on("after_tool_call", afterToolCallHandler);

    // 3. message_received — prompt injection scanning
    const onMessageHandler = createOnMessageHandler({ auditLog, logger: api.logger });
    api.on("message_received", onMessageHandler);

    // 4. gateway_start — auto quick scan on startup
    api.on("gateway_start", async (event) => {
      api.logger.info?.("[claws-defender] Gateway started, running quick scan...");
      auditLog.logStartup({ port: event.port, timestamp: Date.now() });

      try {
        const report = runQuickScan({
          projectRoot: api.resolvePath("."),
          workspaceDir: api.resolvePath("."),
          config: api.config as unknown as Record<string, unknown>,
          baselineDir,
        });

        lastScanReport = report;
        auditLog.logScanReport(report);

        if (report.summary.critical > 0) {
          api.logger.error(
            `[claws-defender] Quick scan found ${report.summary.critical} CRITICAL issues! Run guard_full_scan for details.`,
          );
        } else if (report.summary.high > 0) {
          api.logger.warn(
            `[claws-defender] Quick scan found ${report.summary.high} high-severity issues.`,
          );
        } else {
          api.logger.info?.(
            `[claws-defender] Quick scan complete: ${report.summary.total} findings (${report.completedAt - report.startedAt}ms)`,
          );
        }
      } catch (err) {
        api.logger.error(`[claws-defender] Quick scan failed: ${String(err)}`);
      }
    });

    // -------------------------------------------------------------------
    // Register Agent tools
    // -------------------------------------------------------------------

    // guard_quick_scan
    api.registerTool(
      () => ({
        name: "guard_quick_scan",
        description: "Run a quick security scan (< 10 seconds). Checks plugin integrity, dangerous configs, recent skill code, and memory files.",
        parameters: {
          type: "object" as const,
          properties: {},
        },
        async execute() {
          try {
            const report = runQuickScan({
              projectRoot: api.resolvePath("."),
              workspaceDir: api.resolvePath("."),
              config: api.config as unknown as Record<string, unknown>,
              baselineDir,
            });

            lastScanReport = report;
            auditLog.logScanReport(report);

            return formatScanReport(report);
          } catch (err) {
            return `Quick scan failed: ${String(err)}`;
          }
        },
      }),
      { name: "guard_quick_scan" },
    );

    // guard_full_scan
    api.registerTool(
      () => ({
        name: "guard_full_scan",
        description: "Run a comprehensive security scan (1-5 minutes). Includes full skill scan, dependency CVE check, session DLP, credential audit, and behavior analysis.",
        parameters: {
          type: "object" as const,
          properties: {},
        },
        async execute() {
          try {
            const report = runFullScan({
              projectRoot: api.resolvePath("."),
              workspaceDir: api.resolvePath("."),
              config: api.config as unknown as Record<string, unknown>,
              baselineDir,
              openclawHome,
              recentToolCalls,
            });

            lastScanReport = report;
            auditLog.logScanReport(report);

            return formatScanReport(report);
          } catch (err) {
            return `Full scan failed: ${String(err)}`;
          }
        },
      }),
      { name: "guard_full_scan" },
    );

    // guard_status
    api.registerTool(
      () => ({
        name: "guard_status",
        description: "View the results of the most recent security scan.",
        parameters: {
          type: "object" as const,
          properties: {},
        },
        async execute() {
          if (!lastScanReport) {
            return "No scan has been run yet. Use guard_quick_scan or guard_full_scan to run a security scan.";
          }
          return formatScanReport(lastScanReport);
        },
      }),
      { name: "guard_status" },
    );

    // guard_explain
    api.registerTool(
      () => ({
        name: "guard_explain",
        description: "Get a detailed explanation of a specific security finding by its ID.",
        parameters: {
          type: "object" as const,
          properties: {
            finding_id: {
              type: "string" as const,
              description: "The ID of the finding to explain",
            },
          },
          required: ["finding_id"],
        },
        async execute(params: Record<string, unknown>) {
          const findingId = typeof params.finding_id === "string" ? params.finding_id : "";
          if (!findingId) return "Please provide a finding_id.";

          if (!lastScanReport) {
            return "No scan has been run yet. Run guard_quick_scan first.";
          }

          const finding = findFindingById(lastScanReport, findingId);
          if (!finding) {
            return `Finding "${findingId}" not found. Available finding IDs:\n${listFindingIds(lastScanReport)}`;
          }

          return formatFindingDetail(finding);
        },
      }),
      { name: "guard_explain" },
    );

    api.logger.info?.("[claws-defender] Security defender registered successfully.");
  },
};

// ---------------------------------------------------------------------------
// Report formatting helpers
// ---------------------------------------------------------------------------

function formatScanReport(report: ScanReport): string {
  const { summary, mode, completedAt, startedAt, results } = report;
  const durationMs = completedAt - startedAt;

  const lines: string[] = [
    `## Claws-Defender ${mode === "quick" ? "Quick" : "Full"} Scan Report`,
    ``,
    `**Duration**: ${durationMs}ms | **Total Findings**: ${summary.total}`,
    ``,
    `| Severity | Count |`,
    `|----------|-------|`,
    `| 🔴 Critical | ${summary.critical} |`,
    `| 🟠 High | ${summary.high} |`,
    `| 🟡 Medium | ${summary.medium} |`,
    `| 🔵 Low | ${summary.low} |`,
    `| ℹ️ Info | ${summary.info} |`,
    ``,
  ];

  // Group findings by scanner
  for (const result of results) {
    if (result.findings.length === 0 && !result.error) continue;

    lines.push(`### ${result.scanner}`);

    if (result.error) {
      lines.push(`⚠️ Error: ${result.error}`);
    }

    for (const finding of result.findings) {
      const icon = finding.severity === "critical" ? "🔴" : finding.severity === "high" ? "🟠" : finding.severity === "medium" ? "🟡" : "🔵";
      lines.push(`- ${icon} **${finding.title}** \`${finding.id}\``);
      lines.push(`  ${finding.description}`);
      if (finding.recommendation) {
        lines.push(`  💡 ${finding.recommendation}`);
      }
    }

    lines.push(``);
  }

  if (summary.total === 0) {
    lines.push(`✅ No security issues found.`);
  }

  return lines.join("\n");
}

function findFindingById(report: ScanReport, id: string): ScanFinding | null {
  for (const result of report.results) {
    for (const finding of result.findings) {
      if (finding.id === id) return finding;
    }
  }
  return null;
}

function listFindingIds(report: ScanReport): string {
  const ids: string[] = [];
  for (const result of report.results) {
    for (const finding of result.findings) {
      ids.push(`- \`${finding.id}\` (${finding.severity}: ${finding.title})`);
    }
  }
  return ids.length > 0 ? ids.join("\n") : "(no findings)";
}

function formatFindingDetail(finding: ScanFinding): string {
  return [
    `## Finding: ${finding.title}`,
    ``,
    `**ID**: \`${finding.id}\``,
    `**Severity**: ${finding.severity.toUpperCase()}`,
    `**Scanner**: ${finding.scanner}`,
    finding.file ? `**File**: ${finding.file}${finding.line ? `:${finding.line}` : ""}` : null,
    ``,
    `### Description`,
    finding.description,
    ``,
    finding.recommendation ? `### Recommendation\n${finding.recommendation}` : null,
  ]
    .filter(Boolean)
    .join("\n");
}

export default clawsDefenderPlugin;
