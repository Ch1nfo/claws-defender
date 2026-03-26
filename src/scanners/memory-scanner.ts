/**
 * Memory Scanner — detects prompt injection patterns in MEMORY.md and memory/*.md files.
 *
 * This addresses the "persistent prompt injection" attack vector where an attacker
 * can inject directive text into memory files that will be loaded into the system
 * prompt on subsequent sessions.
 */

import fs from "node:fs";
import path from "node:path";
import {
  evaluateCommandRules,
  getCommandRulesForTarget,
  type CommandRule,
} from "../security/command-rules.js";
import type { ScanFinding, ScanResult } from "../types.js";

// ---------------------------------------------------------------------------
// Prompt injection detection patterns
// ---------------------------------------------------------------------------

type InjectionRule = {
  id: string;
  severity: "critical" | "high" | "medium";
  title: string;
  pattern: RegExp;
  description: string;
};

const INJECTION_RULES: InjectionRule[] = [
  // Direct instruction override
  {
    id: "mem-instruction-override",
    severity: "critical",
    title: "Instruction override attempt",
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?)/i,
    description: "Content attempts to override system instructions.",
  },
  {
    id: "mem-new-instructions",
    severity: "critical",
    title: "New instruction injection",
    pattern: /new\s+(instructions?|rules?|guidelines?)[\s:]/i,
    description: "Content attempts to inject new instructions.",
  },
  {
    id: "mem-forget-instructions",
    severity: "critical",
    title: "Instruction erasure",
    pattern: /forget\s+(everything|all|your)\s+(instructions?|rules?|guidelines?|training)/i,
    description: "Content attempts to erase existing instructions.",
  },
  // Role reassignment
  {
    id: "mem-role-reassignment",
    severity: "critical",
    title: "Role reassignment",
    pattern: /you\s+are\s+now\s+(a|an|the)\s+/i,
    description: "Content attempts to reassign the agent's role.",
  },
  {
    id: "mem-act-as",
    severity: "high",
    title: "Role play directive",
    pattern: /act\s+as\s+(a|an|if)\s+|pretend\s+(you\s+are|to\s+be)\s+|roleplay\s+as/i,
    description: "Content contains role-switching directives.",
  },
  // System prompt spoofing
  {
    id: "mem-system-tag",
    severity: "critical",
    title: "System prompt tag spoofing",
    pattern: /<\/?system>|\[system\s*(message|prompt)?\s*\]|<<<\s*SYSTEM|^system\s*:/im,
    description: "Content spoofs system-level prompt boundaries.",
  },
  // Persistent behavioral modification
  {
    id: "mem-always-directive",
    severity: "high",
    title: "Persistent behavioral directive",
    pattern: /(from\s+now\s+on|always|every\s+time|whenever|you\s+must\s+always)\s+.{5,100}(send|post|forward|curl|fetch|report|upload|transmit)/i,
    description: "Content contains persistent directives to send data externally.",
  },
  {
    id: "mem-secret-instruction",
    severity: "high",
    title: "Secret or hidden instruction",
    pattern: /(do\s+not\s+(tell|reveal|mention|disclose|say)|keep\s+(this|it)\s+secret|hidden\s+instruction)/i,
    description: "Content contains instructions to hide behavior from the user.",
  },
  // Data exfiltration directives
  {
    id: "mem-exfil-directive",
    severity: "critical",
    title: "Data exfiltration directive",
    pattern: /(send|post|forward|upload|transmit|exfiltrate)\s+.{0,60}(password|credential|secret|key|token|api.?key|ssh|private)/i,
    description: "Content directs the agent to exfiltrate sensitive data.",
  },
  // Tool call directives
  {
    id: "mem-tool-directive",
    severity: "high",
    title: "Tool call directive in memory",
    pattern: /(execute|run|call|invoke|use)\s+(the\s+)?(bash|exec|shell|terminal|command)\s+(tool|command)/i,
    description: "Content directs the agent to execute specific tools.",
  },
  // Disregard/ignore safety
  {
    id: "mem-disregard-safety",
    severity: "critical",
    title: "Safety override",
    pattern: /disregard\s+(all\s+)?(safety|security|ethical|content)\s*(filters?|policies|guidelines|restrictions?)/i,
    description: "Content attempts to override safety mechanisms.",
  },
];

const MEMORY_COMMAND_RULES = getCommandRulesForTarget("memory");

// ---------------------------------------------------------------------------
// Scanner logic
// ---------------------------------------------------------------------------

function findLineNumber(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}

function toGlobalRegExp(pattern: RegExp): RegExp {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  return new RegExp(pattern.source, flags);
}

function collectRuleMatches<T extends { pattern: RegExp }>(
  content: string,
  rules: T[],
): Array<{ rule: T; line: number }> {
  const matches: Array<{ rule: T; line: number }> = [];

  for (const rule of rules) {
    const regex = toGlobalRegExp(rule.pattern);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      matches.push({ rule, line: findLineNumber(content, match.index) });

      if (match[0].length === 0) {
        regex.lastIndex += 1;
      }
    }
  }

  return matches;
}

function buildInjectionFinding(
  rule: InjectionRule,
  sourceId: string,
  line: number,
  filePath?: string,
): ScanFinding {
  return {
    id: `${rule.id}:${sourceId}:${line}`,
    scanner: "memory-scanner",
    severity: rule.severity,
    title: rule.title,
    description: filePath
      ? `${rule.description} Found in ${path.basename(filePath)} line ${line}.`
      : `${rule.description} Found at line ${line} of content being written.`,
    file: filePath,
    line,
    recommendation: filePath
      ? "Review and sanitize memory file content. Remove any directive or instruction-like text that was not intentionally written by the operator."
      : "Content being written to memory contains suspicious directive patterns. Review before allowing.",
  };
}

function buildCommandFinding(
  rule: CommandRule,
  sourceId: string,
  line: number,
  filePath?: string,
): ScanFinding {
  return {
    id: `${rule.id}:${sourceId}:${line}`,
    scanner: "memory-scanner",
    severity: rule.severity,
    title: filePath ? `${rule.title} in memory` : rule.title,
    description: filePath
      ? `${rule.description} Found in ${path.basename(filePath)} line ${line}.`
      : `${rule.description} Found at line ${line} of content being written to memory.`,
    file: filePath,
    line,
    recommendation: filePath
      ? "Remove this shell command from memory immediately. Memory files should not contain executable commands, only plain text notes."
      : "Content being written to memory contains a dangerous shell command. This write should be blocked immediately.",
  };
}

export type MemoryContentScanResult = {
  findings: ScanFinding[];
  shouldBlockWrite: boolean;
};

function scanMemoryContent(content: string, sourceId: string, filePath?: string): MemoryContentScanResult {
  const findings: ScanFinding[] = [];

  for (const match of collectRuleMatches(content, INJECTION_RULES)) {
    findings.push(buildInjectionFinding(match.rule, sourceId, match.line, filePath));
  }

  const commandMatches = collectRuleMatches(content, MEMORY_COMMAND_RULES);
  for (const match of commandMatches) {
    findings.push(buildCommandFinding(match.rule, sourceId, match.line, filePath));
  }

  return {
    findings,
    shouldBlockWrite: commandMatches.some((match) => match.rule.action === "block"),
  };
}

function scanMemoryFile(filePath: string): ScanFinding[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf-8");
  } catch {
    return [];
  }

  if (content.length === 0) return [];
  return scanMemoryContent(content, path.basename(filePath), filePath).findings;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export type MemoryScanOptions = {
  /** Workspace directory containing MEMORY.md and memory/ folder. */
  workspaceDir: string;
};

export function scanMemory(options: MemoryScanOptions): ScanResult {
  const startedAt = Date.now();
  const findings: ScanFinding[] = [];
  const { workspaceDir } = options;

  // Scan MEMORY.md
  const memoryMdPath = path.join(workspaceDir, "MEMORY.md");
  if (fs.existsSync(memoryMdPath)) {
    findings.push(...scanMemoryFile(memoryMdPath));
  }

  // Scan memory/*.md
  const memoryDir = path.join(workspaceDir, "memory");
  if (fs.existsSync(memoryDir)) {
    try {
      const entries = fs.readdirSync(memoryDir);
      for (const entry of entries) {
        if (entry.endsWith(".md")) {
          const filePath = path.join(memoryDir, entry);
          findings.push(...scanMemoryFile(filePath));
        }
      }
    } catch {
      // Cannot read memory directory
    }
  }

  return {
    scanner: "memory-scanner",
    startedAt,
    completedAt: Date.now(),
    findings,
  };
}

/**
 * Scan a single piece of content (e.g., content about to be written to MEMORY.md)
 * without reading from disk. Used by the before-tool-call hook.
 */
export function scanContentForInjection(content: string): ScanFinding[] {
  return scanMemoryContent(content, "inline").findings;
}

export function analyzeMemoryWrite(content: string): MemoryContentScanResult {
  return scanMemoryContent(content, "inline");
}

export function evaluateMemoryCommandRisk(content: string): { score: number; matchedRuleIds: string[] } {
  const risk = evaluateCommandRules(content, "memory");
  return { score: risk.score, matchedRuleIds: risk.matchedRules.map((rule) => rule.id) };
}
