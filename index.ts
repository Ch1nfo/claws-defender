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
import {
  definePluginEntry,
  emptyPluginConfigSchema,
  type OpenClawPluginApi,
} from "openclaw/plugin-sdk/plugin-entry";
import { textResult, type AnyAgentTool } from "openclaw/plugin-sdk/agent-runtime";
import { AuditLog } from "./src/audit/immutable-log.js";
import { createAfterToolCallHandler } from "./src/hooks/after-tool-call.js";
import { createBeforeToolCallHandler } from "./src/hooks/before-tool-call.js";
import { createOnMessageHandler } from "./src/hooks/on-message.js";
import { createMemorySemanticAnalyzer } from "./src/llm/memory-semantic-analyzer.js";
import { runFullScan } from "./src/scan/full-scan.js";
import { runQuickScan } from "./src/scan/quick-scan.js";
import type { ScanFinding, ScanReport, ToolCallRecord } from "./src/types.js";

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

const recentToolCalls: ToolCallRecord[] = [];
let lastScanReport: ScanReport | null = null;

function resolveWorkspaceDir(api: OpenClawPluginApi): string {
  return api.config?.agents?.defaults?.workspace?.trim() || process.cwd() || api.resolvePath(".");
}

function resolveScanRoots(api: OpenClawPluginApi): { projectRoot: string; workspaceDir: string } {
  const workspaceDir = resolveWorkspaceDir(api);
  return {
    // The plugin is installed under ~/.openclaw/extensions/<id>, so scans should
    // target the host workspace/gateway cwd instead of the plugin install dir.
    projectRoot: process.cwd() || workspaceDir,
    workspaceDir,
  };
}

// ---------------------------------------------------------------------------
// Plugin definition
// ---------------------------------------------------------------------------

const clawsDefenderPlugin = definePluginEntry({
  id: "claws-defender",
  name: "Claws-Defender",
  description: "Agent OS runtime security defender — tool call interception, prompt injection scanning, and dual-mode security scanning",
  configSchema: emptyPluginConfigSchema(),

  register(api: OpenClawPluginApi) {
    const openclawHome = path.join(process.env.HOME ?? "~", ".openclaw");
    const baselineDir = path.join(openclawHome, "claws-defender");
    const auditLog = new AuditLog(baselineDir);
    const createSemanticAnalyzer = () =>
      createMemorySemanticAnalyzer({
        runEmbeddedPiAgent: api.runtime.agent.runEmbeddedPiAgent,
        resolveAgentTimeoutMs: api.runtime.agent.resolveAgentTimeoutMs,
        config: api.config,
        logger: api.logger,
      });
    const semanticAnalyzer = createSemanticAnalyzer();

    // -------------------------------------------------------------------
    // Register hooks
    // -------------------------------------------------------------------

    // 1. before_tool_call — semantic firewall (high priority to run first)
    const beforeToolCallHandler = createBeforeToolCallHandler({
      auditLog,
      recentToolCalls,
      semanticAnalyzer,
      logger: api.logger,
      resolveWorkspaceDir: () => resolveWorkspaceDir(api),
    });
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
        const { projectRoot, workspaceDir } = resolveScanRoots(api);
        const report = runQuickScan({
          projectRoot,
          workspaceDir,
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
    api.registerTool({
      name: "guard_quick_scan",
      description: "Run a quick security scan (< 10 seconds). Checks plugin integrity, dangerous configs, recent skill code, and memory files.",
      parameters: {
        type: "object" as const,
        properties: {},
      },
      async execute() {
        try {
          const { projectRoot, workspaceDir } = resolveScanRoots(api);
          const report = runQuickScan({
            projectRoot,
            workspaceDir,
            config: api.config as unknown as Record<string, unknown>,
            baselineDir,
          });

          lastScanReport = report;
          auditLog.logScanReport(report);

          return textResult(formatScanReport(report), report);
        } catch (err) {
          const message = `Quick scan failed: ${String(err)}`;
          return textResult(message, { ok: false, error: message });
        }
      },
    } as AnyAgentTool);

    // guard_full_scan
    api.registerTool({
      name: "guard_full_scan",
      description: "Run a comprehensive security scan (1-5 minutes). Includes full skill scan, dependency CVE check, session DLP, credential audit, and behavior analysis.",
      parameters: {
        type: "object" as const,
        properties: {},
      },
      async execute() {
        try {
          const { projectRoot, workspaceDir } = resolveScanRoots(api);
          const fullScanSemanticAnalyzer = createSemanticAnalyzer();
          const report = await runFullScan({
            projectRoot,
            workspaceDir,
            config: api.config as unknown as Record<string, unknown>,
            baselineDir,
            openclawHome,
            recentToolCalls,
            semanticAnalyzer: fullScanSemanticAnalyzer,
          });

          lastScanReport = report;
          auditLog.logScanReport(report);

          return textResult(formatScanReport(report), report);
        } catch (err) {
          const message = `Full scan failed: ${String(err)}`;
          return textResult(message, { ok: false, error: message });
        }
      },
    } as AnyAgentTool);

    // guard_status
    api.registerTool({
      name: "guard_status",
      description: "View the results of the most recent security scan.",
      parameters: {
        type: "object" as const,
        properties: {},
      },
      async execute() {
        if (!lastScanReport) {
          const message =
            "No scan has been run yet. Use guard_quick_scan or guard_full_scan to run a security scan.";
          return textResult(message, { ok: false, error: message });
        }
        return textResult(formatScanReport(lastScanReport), lastScanReport);
      },
    } as AnyAgentTool);

    // guard_explain
    api.registerTool({
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
      async execute(_toolCallId, params: Record<string, unknown>) {
        const findingId = typeof params.finding_id === "string" ? params.finding_id : "";
        if (!findingId) {
          const message = "Please provide a finding_id.";
          return textResult(message, { ok: false, error: message });
        }

        if (!lastScanReport) {
          const message = "No scan has been run yet. Run guard_quick_scan first.";
          return textResult(message, { ok: false, error: message });
        }

        const finding = findFindingById(lastScanReport, findingId);
        if (!finding) {
          const message = `Finding "${findingId}" not found. Available finding IDs:\n${listFindingIds(lastScanReport)}`;
          return textResult(message, {
            ok: false,
            error: message,
            availableFindingIds: listFindingIds(lastScanReport),
          });
        }

        return textResult(formatFindingDetail(finding), finding);
      },
    } as AnyAgentTool);

    api.logger.info?.("[claws-defender] Security defender registered successfully.");
  },
});

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
