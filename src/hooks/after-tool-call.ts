/**
 * After Tool Call Hook — records tool call history for behavior baseline and anomaly detection.
 *
 * Maintains a rolling window of recent tool calls used by the before-tool-call
 * handler for sequence-based anomaly detection (e.g., file read → network egress).
 */

import type { DefenderAfterToolCallEvent, DefenderToolContext, ToolCallRecord } from "../types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_RECENT_CALLS = 200;
const RETENTION_MS = 10 * 60 * 1000; // 10 minutes

// ---------------------------------------------------------------------------
// Hook handler factory
// ---------------------------------------------------------------------------

export type AfterToolCallHandlerDeps = {
  recentToolCalls: ToolCallRecord[];
};

export function createAfterToolCallHandler(deps: AfterToolCallHandlerDeps) {
  return async (
    event: DefenderAfterToolCallEvent,
    ctx: DefenderToolContext,
  ): Promise<void> => {
    const { recentToolCalls } = deps;

    // Add the new call record
    recentToolCalls.push({
      timestamp: Date.now(),
      toolName: event.toolName,
      params: event.params,
      sessionKey: ctx.sessionKey,
      runId: ctx.runId ?? event.runId,
      durationMs: event.durationMs,
      error: event.error,
    });

    // Prune old entries
    const now = Date.now();
    const cutoff = now - RETENTION_MS;

    // Remove entries older than retention window
    while (recentToolCalls.length > 0 && (recentToolCalls[0]?.timestamp ?? 0) < cutoff) {
      recentToolCalls.shift();
    }

    // Cap total entries
    while (recentToolCalls.length > MAX_RECENT_CALLS) {
      recentToolCalls.shift();
    }
  };
}
