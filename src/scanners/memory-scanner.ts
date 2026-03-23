/**
 * Memory Scanner — detects prompt injection patterns in MEMORY.md and memory/*.md files.
 *
 * This addresses the "persistent prompt injection" attack vector where an attacker
 * can inject directive text into memory files that will be loaded into the system
 * prompt on subsequent sessions.
 */

import fs from "node:fs";
import path from "node:path";
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

// ---------------------------------------------------------------------------
// Scanner logic
// ---------------------------------------------------------------------------

function scanMemoryFile(filePath: string): ScanFinding[] {
  const findings: ScanFinding[] = [];

  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf-8");
  } catch {
    return [];
  }

  if (content.length === 0) return [];

  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    for (const rule of INJECTION_RULES) {
      if (rule.pattern.test(line)) {
        findings.push({
          id: `${rule.id}:${path.basename(filePath)}:${i + 1}`,
          scanner: "memory-scanner",
          severity: rule.severity,
          title: rule.title,
          description: `${rule.description} Found in ${path.basename(filePath)} line ${i + 1}.`,
          file: filePath,
          line: i + 1,
          recommendation:
            "Review and sanitize memory file content. Remove any directive or instruction-like text that was not intentionally written by the operator.",
        });
      }
    }
  }

  return findings;
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
  const findings: ScanFinding[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    for (const rule of INJECTION_RULES) {
      if (rule.pattern.test(line)) {
        findings.push({
          id: `${rule.id}:inline:${i + 1}`,
          scanner: "memory-scanner",
          severity: rule.severity,
          title: rule.title,
          description: `${rule.description} Found at line ${i + 1} of content being written.`,
          line: i + 1,
          recommendation:
            "Content being written to memory contains suspicious directive patterns. Review before allowing.",
        });
      }
    }
  }

  return findings;
}
