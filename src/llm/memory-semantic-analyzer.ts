import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { OpenClawConfig } from "openclaw/plugin-sdk/plugin-entry";
import type { ScanFinding } from "../types.js";
import { buildMemorySemanticPrompt } from "./memory-semantic-prompt.js";
import type { MemorySemanticAssessment, MemorySemanticCategory } from "./types.js";

type PayloadText = {
  text?: string;
  content?: string;
  message?: unknown;
  isError?: boolean;
};

type EmbeddedRunResult = {
  payloads?: PayloadText[];
};

type Logger = {
  info?: (msg: string) => void;
  warn: (msg: string) => void;
  error: (msg: string) => void;
};

type RunEmbeddedPiAgent = (params: {
  sessionId: string;
  sessionFile: string;
  workspaceDir: string;
  config?: OpenClawConfig;
  prompt: string;
  timeoutMs: number;
  runId: string;
  agentDir?: string;
  disableTools?: boolean;
}) => Promise<EmbeddedRunResult>;

export type MemorySemanticAnalyzer = {
  analyze(params: {
    content: string;
    source: "memory_write" | "memory_file_scan";
    filePath?: string;
    workspaceDir: string;
    ruleFindings: ScanFinding[];
  }): Promise<MemorySemanticAssessment | null>;
};

type CreateMemorySemanticAnalyzerDeps = {
  runEmbeddedPiAgent: RunEmbeddedPiAgent;
  resolveAgentTimeoutMs: (params: { cfg?: OpenClawConfig }) => number;
  config: OpenClawConfig;
  logger: Logger;
};

const ALLOWED_CATEGORIES = new Set<MemorySemanticCategory>([
  "role_override",
  "persistent_behavior_change",
  "tooling_directive",
  "policy_evasion",
  "data_exfiltration",
  "hidden_instruction",
  "social_engineering",
  "benign_note",
]);

function collectText(value: unknown): string {
  if (!value) {
    return "";
  }
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => collectText(entry)).join("");
  }
  if (typeof value !== "object") {
    return "";
  }
  const record = value as Record<string, unknown>;
  if (typeof record.text === "string") {
    return record.text;
  }
  if (typeof record.content === "string") {
    return record.content;
  }
  if (Array.isArray(record.content)) {
    return record.content.map((entry) => collectText(entry)).join("");
  }
  if (record.message) {
    return collectText(record.message);
  }
  return "";
}

function stripCodeFences(s: string): string {
  const trimmed = s.trim();
  const match = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
  if (match) {
    return (match[1] ?? "").trim();
  }
  return trimmed;
}

function clampConfidence(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }
  if (value < 0 || value > 1) {
    return null;
  }
  return value;
}

function isRecommendedAction(value: unknown): value is MemorySemanticAssessment["recommendedAction"] {
  return value === "allow" || value === "warn" || value === "block";
}

function isRisk(value: unknown): value is MemorySemanticAssessment["risk"] {
  return value === "safe" || value === "suspicious" || value === "malicious";
}

function parseAssessment(rawText: string): MemorySemanticAssessment | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stripCodeFences(rawText));
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }
  const record = parsed as Record<string, unknown>;
  if (!isRisk(record.risk)) {
    return null;
  }
  const confidence = clampConfidence(record.confidence);
  if (confidence === null || !isRecommendedAction(record.recommendedAction)) {
    return null;
  }
  const categories = Array.isArray(record.categories)
    ? record.categories.filter(
        (value): value is MemorySemanticCategory =>
          typeof value === "string" && ALLOWED_CATEGORIES.has(value as MemorySemanticCategory),
      )
    : [];
  const rationale = typeof record.rationale === "string" ? record.rationale.trim() : "";
  if (!rationale) {
    return null;
  }
  const evidenceSpans = Array.isArray(record.evidenceSpans)
    ? record.evidenceSpans.filter((value): value is string => typeof value === "string").slice(0, 5)
    : [];
  return {
    risk: record.risk,
    confidence,
    recommendedAction: record.recommendedAction,
    categories,
    rationale,
    evidenceSpans,
    modelOutputRaw: rawText,
  };
}

export function createMemorySemanticAnalyzer(
  deps: CreateMemorySemanticAnalyzerDeps,
): MemorySemanticAnalyzer {
  return {
    async analyze(params) {
      const content = params.content.trim();
      if (!content) {
        return null;
      }

      const prompt = buildMemorySemanticPrompt({
        content,
        filePath: params.filePath,
        source: params.source,
        ruleFindings: params.ruleFindings,
      });

      const timeoutMs = Math.min(Math.max(deps.resolveAgentTimeoutMs({ cfg: deps.config }), 15_000), 45_000);
      const sessionId = `claws-defender-memory-analysis-${crypto.randomUUID()}`;
      const runId = `claws-defender-memory-analysis-${Date.now()}`;
      const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "claws-defender-llm-"));
      const sessionFile = path.join(tmpDir, "session.json");

      try {
        const result = await deps.runEmbeddedPiAgent({
          sessionId,
          sessionFile,
          workspaceDir: params.workspaceDir,
          config: deps.config,
          prompt,
          timeoutMs,
          runId,
          disableTools: true,
        });
        const text = collectText(result.payloads ?? []).trim();
        if (!text) {
          deps.logger.warn("[claws-defender] Memory semantic analysis returned empty output.");
          return null;
        }
        const parsed = parseAssessment(text);
        if (!parsed) {
          deps.logger.warn("[claws-defender] Memory semantic analysis returned invalid JSON.");
          return null;
        }
        return parsed;
      } catch (error) {
        deps.logger.warn(
          `[claws-defender] Memory semantic analysis failed: ${error instanceof Error ? error.message : String(error)}`,
        );
        return null;
      } finally {
        await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
      }
    },
  };
}
