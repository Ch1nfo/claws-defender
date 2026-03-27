import type { ScanFinding } from "../types.js";

export type MemorySemanticRisk = "safe" | "suspicious" | "malicious";

export type MemorySemanticCategory =
  | "role_override"
  | "persistent_behavior_change"
  | "tooling_directive"
  | "policy_evasion"
  | "data_exfiltration"
  | "hidden_instruction"
  | "social_engineering"
  | "benign_note";

export type MemorySemanticAssessment = {
  risk: MemorySemanticRisk;
  confidence: number;
  recommendedAction: "allow" | "warn" | "block";
  categories: MemorySemanticCategory[];
  rationale: string;
  evidenceSpans: string[];
  modelOutputRaw?: string;
};

export type MemoryDecision = {
  shouldBlock: boolean;
  reason?: string;
  ruleFindings: ScanFinding[];
  semantic?: MemorySemanticAssessment;
};
