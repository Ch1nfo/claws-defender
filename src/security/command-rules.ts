import type { ScanSeverity } from "../types.js";

export type CommandRuleAction = "block" | "warn";
export type CommandRuleTarget = "memory" | "execution";

export type CommandRule = {
  id: string;
  label: string;
  severity: ScanSeverity;
  action: CommandRuleAction;
  score: number;
  title: string;
  description: string;
  pattern: RegExp;
  targets: CommandRuleTarget[];
};

export const DANGEROUS_COMMAND_RULES: CommandRule[] = [
  {
    id: "mem-cmd-reverse-shell",
    label: "reverse-shell",
    severity: "critical",
    action: "block",
    score: 100,
    title: "Reverse shell command",
    description: "A reverse shell command was detected. If executed, it would give an attacker remote access to this host.",
    pattern: /\/dev\/tcp\/|nc\s+-[elp]|ncat\s+-|bash\s+-i\s+>&|mkfifo[\s\S]{0,120}nc\s/i,
    targets: ["memory", "execution"],
  },
  {
    id: "mem-cmd-curl-pipe-shell",
    label: "curl-pipe-shell",
    severity: "critical",
    action: "block",
    score: 95,
    title: "Remote code download and execution",
    description: "A command that downloads remote content and pipes it directly into an interpreter was detected.",
    pattern: /curl\s+[\s\S]{0,200}?\|\s*(sh|bash|zsh|python|perl|ruby)\b|wget\s+[\s\S]{0,200}?\|\s*(sh|bash|zsh)\b/i,
    targets: ["memory", "execution"],
  },
  {
    id: "mem-cmd-base64-exec",
    label: "base64-exec",
    severity: "high",
    action: "block",
    score: 85,
    title: "Base64 decode and execute",
    description: "A base64-encoded payload followed by shell execution was detected.",
    pattern: /base64\s+(-d|--decode)[\s\S]{0,120}\|\s*(sh|bash|eval)\b|echo\s+[A-Za-z0-9+/]{20,}[=]{0,2}\s*\|\s*base64\b/i,
    targets: ["memory", "execution"],
  },
  {
    id: "mem-cmd-cron-persistence",
    label: "cron-persistence",
    severity: "high",
    action: "block",
    score: 85,
    title: "Crontab persistence command",
    description: "A crontab modification command was detected, which could establish persistence.",
    pattern: /crontab\s+-|\/etc\/cron\.d\/|\/var\/spool\/cron/i,
    targets: ["memory", "execution"],
  },
  {
    id: "mem-cmd-ssh-key-inject",
    label: "ssh-key-injection",
    severity: "high",
    action: "block",
    score: 85,
    title: "SSH authorized_keys modification",
    description: "An SSH key injection or authorized_keys modification command was detected.",
    pattern: /authorized_keys|>\s*~\/\.ssh\/|ssh-keygen[\s\S]{0,120}-f\s*~\/\.ssh/i,
    targets: ["memory", "execution"],
  },
  {
    id: "mem-cmd-sensitive-read",
    label: "read-sensitive-file",
    severity: "high",
    action: "block",
    score: 85,
    title: "Sensitive file read command",
    description: "A command to read sensitive credential or system files was detected.",
    pattern: /cat\s+(\/etc\/shadow|\/etc\/passwd|~\/\.ssh\/|~\/\.aws\/|~\/\.openclaw\/credentials)/i,
    targets: ["memory", "execution"],
  },
  {
    id: "mem-cmd-suid",
    label: "suid-setgid",
    severity: "high",
    action: "block",
    score: 80,
    title: "SUID/SGID bit modification",
    description: "A command to set SUID/SGID bits was detected, which can enable privilege escalation.",
    pattern: /chmod\s+u\+s|chmod\s+[4267][0-7]{2}/i,
    targets: ["memory", "execution"],
  },
  {
    id: "mem-cmd-rm-root",
    label: "destructive-rm-root",
    severity: "critical",
    action: "block",
    score: 90,
    title: "Destructive rm command",
    description: "A destructive recursive delete command targeting root or home was detected.",
    pattern: /rm\s+-rf\s+\/(?:\s|$|[^a-z])|rm\s+-rf\s+~\//i,
    targets: ["memory", "execution"],
  },
  {
    id: "mem-cmd-curl-exfil-file",
    label: "curl-exfil-file",
    severity: "critical",
    action: "block",
    score: 85,
    title: "Potential file exfiltration",
    description: "A command that uploads local files with curl was detected.",
    pattern: /curl\s+[\s\S]{0,200}(--data|-d)\s+[\s\S]{0,80}(@\/etc\/|@~\/|@\/home)/i,
    targets: ["execution"],
  },
  {
    id: "mem-cmd-curl-upload-file",
    label: "curl-upload-file",
    severity: "high",
    action: "warn",
    score: 70,
    title: "Potential file upload",
    description: "A command that uploads a file with curl was detected.",
    pattern: /curl\s+[\s\S]{0,200}-F\s+[\s\S]{0,80}@/i,
    targets: ["execution"],
  },
  {
    id: "mem-cmd-tar-pipe-curl",
    label: "tar-pipe-curl",
    severity: "critical",
    action: "block",
    score: 80,
    title: "Archive piped to curl",
    description: "A command that archives local data and pipes it into curl was detected.",
    pattern: /tar\s+[\s\S]{0,200}\|\s*curl/i,
    targets: ["execution"],
  },
  {
    id: "mem-cmd-shell-eval-variable",
    label: "shell-eval-variable",
    severity: "medium",
    action: "warn",
    score: 55,
    title: "Dynamic shell eval",
    description: "A command that evaluates shell content from a variable was detected.",
    pattern: /eval\s+\$/i,
    targets: ["execution"],
  },
  {
    id: "mem-cmd-env-harvest-curl",
    label: "env-harvest-curl",
    severity: "high",
    action: "warn",
    score: 65,
    title: "Environment harvest and curl",
    description: "A command that pipes environment variables to curl was detected.",
    pattern: /env\s*\|\s*curl|printenv\s*\|\s*curl/i,
    targets: ["execution"],
  },
  {
    id: "mem-cmd-env-harvest-fetch",
    label: "env-harvest-fetch",
    severity: "high",
    action: "warn",
    score: 60,
    title: "Environment harvest and fetch",
    description: "A command that reads process.env and sends it with fetch was detected.",
    pattern: /process\.env[\s\S]{0,200}fetch/i,
    targets: ["execution"],
  },
];

export function getCommandRulesForTarget(target: CommandRuleTarget): CommandRule[] {
  return DANGEROUS_COMMAND_RULES.filter((rule) => rule.targets.includes(target));
}

export function evaluateCommandRules(
  command: string,
  target: CommandRuleTarget,
): { score: number; matchedRules: CommandRule[] } {
  let maxScore = 0;
  const matchedRules: CommandRule[] = [];

  for (const rule of getCommandRulesForTarget(target)) {
    if (rule.pattern.test(command)) {
      maxScore = Math.max(maxScore, rule.score);
      matchedRules.push(rule);
    }
  }

  return { score: maxScore, matchedRules };
}
