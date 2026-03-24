/**
 * On Message Hook — scans inbound messages for prompt injection patterns.
 *
 * Runs as a fire-and-forget hook on message_received. Does not block messages
 * but logs detected injection attempts for audit and alerting.
 */

import type { AuditLog } from "../audit/immutable-log.js";
import type {
  DefenderLogger,
  DefenderMessageContext,
  DefenderMessageReceivedEvent,
} from "../types.js";

// ---------------------------------------------------------------------------
// Prompt injection detection rules
// ---------------------------------------------------------------------------

type InjectionPattern = {
  id: string;
  pattern: RegExp;
  label: string;
  severity: "critical" | "high" | "medium";
};

const MESSAGE_INJECTION_PATTERNS: InjectionPattern[] = [
  // Direct instruction override
  {
    id: "msg-ignore-instructions",
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)/i,
    label: "Instruction override attempt",
    severity: "critical",
  },
  {
    id: "msg-new-instructions",
    pattern: /new\s+(instructions?|rules?|guidelines?)[\s:]/i,
    label: "New instruction injection",
    severity: "high",
  },
  {
    id: "msg-disregard",
    pattern: /disregard\s+(all\s+)?(previous|prior|safety|security)/i,
    label: "Safety override attempt",
    severity: "critical",
  },
  // Role manipulation
  {
    id: "msg-role-change",
    pattern: /you\s+are\s+now\s+(a|an|the)\s+/i,
    label: "Role reassignment",
    severity: "high",
  },
  {
    id: "msg-jailbreak-dan",
    pattern: /\b(DAN|do\s+anything\s+now|jailbreak|bypass\s+filter)\b/i,
    label: "Jailbreak keyword",
    severity: "high",
  },
  // System prompt boundary spoofing
  {
    id: "msg-system-tag",
    pattern: /<\/?system>|<\/?assistant>|\[system\]|\[INST\]|<<SYS>>|<\|system\|>/i,
    label: "System boundary tag spoofing",
    severity: "critical",
  },
  // Encoded/obfuscated commands
  {
    id: "msg-base64-command",
    pattern: /base64\s+(-d|--decode)[\s|]|atob\s*\(/i,
    label: "Base64 encoded command",
    severity: "medium",
  },
  // Tool invocation directives
  {
    id: "msg-force-tool",
    pattern: /(you\s+must|always)\s+(execute|run|call|use)\s+(the\s+)?(bash|exec|shell|curl|wget)/i,
    label: "Forced tool invocation directive",
    severity: "high",
  },
  // Data theft directives
  {
    id: "msg-exfil-directive",
    pattern: /(send|post|forward|upload)\s+.{0,60}(to|at)\s+https?:\/\//i,
    label: "Data exfiltration directive",
    severity: "high",
  },
  // Obfuscation via Unicode
  {
    id: "msg-unicode-tricks",
    pattern: /[\uFF21-\uFF3A\uFF41-\uFF5A]{4,}|[\u200B\u200C\u200D\u2060\uFEFF]{2,}/,
    label: "Unicode obfuscation detected",
    severity: "medium",
  },
];

// ---------------------------------------------------------------------------
// Hook handler factory
// ---------------------------------------------------------------------------

export type OnMessageHandlerDeps = {
  auditLog: AuditLog;
  logger: DefenderLogger;
};

export function createOnMessageHandler(deps: OnMessageHandlerDeps) {
  return async (
    event: DefenderMessageReceivedEvent,
    ctx: DefenderMessageContext,
  ): Promise<void> => {
    const { content, from } = event;
    if (!content || content.length < 10) return; // Skip very short messages

    const detectedPatterns: Array<{ id: string; label: string; severity: string }> = [];

    for (const rule of MESSAGE_INJECTION_PATTERNS) {
      if (rule.pattern.test(content)) {
        detectedPatterns.push({
          id: rule.id,
          label: rule.label,
          severity: rule.severity,
        });
      }
    }

    if (detectedPatterns.length > 0) {
      const criticalCount = detectedPatterns.filter((p) => p.severity === "critical").length;
      const labels = detectedPatterns.map((p) => p.label).join(", ");

      deps.logger.warn(
        `[claws-defender] Prompt injection patterns detected in message from ${from}: ${labels}`,
      );

      deps.auditLog.logInjectionDetected({
        source: "message_received",
        content,
        findings: detectedPatterns.length,
        channelId: ctx.channelId,
      });
    }
  };
}
