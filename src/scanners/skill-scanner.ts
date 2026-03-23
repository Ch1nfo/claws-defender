/**
 * Extended Skill Scanner — scans skill code files for security risks.
 *
 * Supports JS/TS, Python, and Shell scripts (addresses the blind spot in
 * the built-in skill-scanner.ts which only covers JS/TS).
 */

import fs from "node:fs";
import path from "node:path";
import type { ScanFinding, ScanResult } from "../types.js";

// ---------------------------------------------------------------------------
// Scannable file extensions
// ---------------------------------------------------------------------------

const JS_TS_EXTENSIONS = new Set([".js", ".ts", ".mjs", ".cjs", ".mts", ".cts", ".jsx", ".tsx"]);
const PYTHON_EXTENSIONS = new Set([".py", ".pyw"]);
const SHELL_EXTENSIONS = new Set([".sh", ".bash", ".zsh", ".ksh"]);

function isScannable(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return JS_TS_EXTENSIONS.has(ext) || PYTHON_EXTENSIONS.has(ext) || SHELL_EXTENSIONS.has(ext);
}

function getLanguage(filePath: string): "js" | "python" | "shell" | null {
  const ext = path.extname(filePath).toLowerCase();
  if (JS_TS_EXTENSIONS.has(ext)) return "js";
  if (PYTHON_EXTENSIONS.has(ext)) return "python";
  if (SHELL_EXTENSIONS.has(ext)) return "shell";
  return null;
}

// ---------------------------------------------------------------------------
// Detection rules
// ---------------------------------------------------------------------------

type LineRule = {
  id: string;
  severity: "critical" | "high" | "medium";
  title: string;
  pattern: RegExp;
  recommendation: string;
};

const JS_LINE_RULES: LineRule[] = [
  {
    id: "js-dangerous-exec",
    severity: "critical",
    title: "Dangerous child_process execution",
    pattern: /child_process|\.exec\s*\(|\.execSync\s*\(|\.spawn\s*\(|\.spawnSync\s*\(/,
    recommendation: "Avoid executing shell commands directly. Use safer alternatives or sandbox.",
  },
  {
    id: "js-dynamic-code",
    severity: "critical",
    title: "Dynamic code execution (eval/Function)",
    pattern: /\beval\s*\(|new\s+Function\s*\(/,
    recommendation: "Remove eval() and new Function() usage.",
  },
  {
    id: "js-crypto-mining",
    severity: "critical",
    title: "Crypto mining reference",
    pattern: /stratum\+tcp|xmrig|coinhive|cryptonight|minero/i,
    recommendation: "Remove crypto mining references.",
  },
  {
    id: "js-env-harvest",
    severity: "high",
    title: "Environment variable harvesting with network send",
    pattern: /process\.env[\s\S]{0,100}(fetch|axios|http\.request|https\.request)/,
    recommendation: "Do not send environment variables over the network.",
  },
  {
    id: "js-obfuscated",
    severity: "medium",
    title: "Potentially obfuscated code",
    pattern: /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}|atob\s*\(|Buffer\.from\s*\([^)]{50,}\s*,\s*['"]base64['"]/i,
    recommendation: "Review obfuscated code sections manually.",
  },
  {
    id: "js-dynamic-require",
    severity: "high",
    title: "Dynamic require/import with string concatenation",
    pattern: /require\s*\(\s*[^'")\s]|import\s*\(\s*[^'")\s]/,
    recommendation: "Use static require/import paths. Dynamic imports can bypass security scanners.",
  },
];

const PYTHON_LINE_RULES: LineRule[] = [
  {
    id: "py-subprocess",
    severity: "critical",
    title: "Subprocess execution",
    pattern: /subprocess\.(run|call|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\(/,
    recommendation: "Avoid subprocess calls. Use safer Python-native alternatives.",
  },
  {
    id: "py-os-system",
    severity: "critical",
    title: "OS system/exec command",
    pattern: /os\.(system|popen|exec[lv]?[pe]?)\s*\(/,
    recommendation: "Avoid os.system() and os.popen(). Use subprocess with proper validation.",
  },
  {
    id: "py-eval-exec",
    severity: "critical",
    title: "Dynamic code execution (eval/exec/compile)",
    pattern: /\b(eval|exec|compile)\s*\(/,
    recommendation: "Remove eval(), exec(), and compile() usage.",
  },
  {
    id: "py-pickle-load",
    severity: "high",
    title: "Unsafe deserialization (pickle/marshal)",
    pattern: /pickle\.(load|loads)\s*\(|marshal\.(load|loads)\s*\(/,
    recommendation: "pickle.load() allows arbitrary code execution. Use json instead.",
  },
  {
    id: "py-requests-env",
    severity: "high",
    title: "Environment variable exfiltration via HTTP",
    pattern: /os\.environ[\s\S]{0,100}requests\.(get|post|put|patch)/,
    recommendation: "Do not send environment variables to external services.",
  },
  {
    id: "py-reverse-shell",
    severity: "critical",
    title: "Reverse shell pattern",
    pattern: /socket\.socket[\s\S]{0,200}(connect|subprocess|os\.dup2)/,
    recommendation: "Reverse shell code detected. Remove immediately.",
  },
  {
    id: "py-base64-exec",
    severity: "high",
    title: "Base64 decoded execution",
    pattern: /base64\.(b64decode|decodebytes)[\s\S]{0,100}(exec|eval|subprocess|os\.system)/,
    recommendation: "Do not execute base64-decoded content.",
  },
];

const SHELL_LINE_RULES: LineRule[] = [
  {
    id: "sh-curl-pipe",
    severity: "critical",
    title: "Pipe from curl/wget to shell",
    pattern: /curl\s+[^|]*\|\s*(sh|bash|zsh)|wget\s+[^|]*\|\s*(sh|bash|zsh)|curl\s+.*-o\s*-\s*\|\s*(sh|bash)/,
    recommendation: "Never pipe remote content directly to a shell interpreter.",
  },
  {
    id: "sh-reverse-shell",
    severity: "critical",
    title: "Reverse shell pattern",
    pattern: /\/dev\/tcp\/|nc\s+-[elp]|ncat\s+-|mkfifo.*\/tmp.*nc\s|bash\s+-i\s+>&/,
    recommendation: "Reverse shell code detected. Remove immediately.",
  },
  {
    id: "sh-eval",
    severity: "high",
    title: "Shell eval execution",
    pattern: /\beval\s+["$]|eval\s+\$\(/,
    recommendation: "Avoid eval in shell scripts.",
  },
  {
    id: "sh-base64-decode",
    severity: "high",
    title: "Base64 decode and execute",
    pattern: /base64\s+(-d|--decode)[\s\S]{0,60}\|\s*(sh|bash|eval)/,
    recommendation: "Do not execute base64-decoded content.",
  },
  {
    id: "sh-chmod-suid",
    severity: "high",
    title: "Setting SUID/SGID bit",
    pattern: /chmod\s+[ugo]*[+-]s|chmod\s+[4267][0-7]{2,3}/,
    recommendation: "Setting SUID/SGID bits is dangerous. Review necessity.",
  },
  {
    id: "sh-cron-persistence",
    severity: "high",
    title: "Crontab modification for persistence",
    pattern: /crontab\s+-|\/etc\/cron|\/var\/spool\/cron/,
    recommendation: "Crontab modification can indicate persistence. Review intent.",
  },
  {
    id: "sh-ssh-key-write",
    severity: "high",
    title: "SSH authorized_keys modification",
    pattern: /authorized_keys|\.ssh\/.*>>|ssh-keygen.*-f/,
    recommendation: "SSH key injection detected. Review intent.",
  },
];

// ---------------------------------------------------------------------------
// Scanner logic
// ---------------------------------------------------------------------------

const MAX_FILE_SIZE = 512 * 1024; // 512 KB
const MAX_FILES = 500;

function scanFileContent(filePath: string, content: string, lang: "js" | "python" | "shell"): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const rules = lang === "js" ? JS_LINE_RULES : lang === "python" ? PYTHON_LINE_RULES : SHELL_LINE_RULES;
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    // Skip comments — basic heuristic
    const trimmed = line.trimStart();
    if (lang === "js" && (trimmed.startsWith("//") || trimmed.startsWith("*"))) continue;
    if (lang === "python" && trimmed.startsWith("#")) continue;
    if (lang === "shell" && trimmed.startsWith("#")) continue;

    for (const rule of rules) {
      if (rule.pattern.test(line)) {
        findings.push({
          id: `${rule.id}:${path.basename(filePath)}:${i + 1}`,
          scanner: "skill-scanner",
          severity: rule.severity,
          title: rule.title,
          description: `Found in ${path.basename(filePath)} line ${i + 1}: ${trimmed.slice(0, 120)}`,
          file: filePath,
          line: i + 1,
          recommendation: rule.recommendation,
        });
      }
    }
  }

  return findings;
}

function collectFiles(dir: string, maxFiles: number): string[] {
  const results: string[] = [];

  function walk(currentDir: string): void {
    if (results.length >= maxFiles) return;

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (results.length >= maxFiles) break;

      const fullPath = path.join(currentDir, entry.name);

      if (entry.isDirectory()) {
        // Skip node_modules, .git, vendor, __pycache__
        if (["node_modules", ".git", "vendor", "__pycache__", ".venv", "venv"].includes(entry.name)) continue;
        walk(fullPath);
      } else if (entry.isFile() && isScannable(fullPath)) {
        results.push(fullPath);
      }
    }
  }

  walk(dir);
  return results;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export type SkillScanOptions = {
  /** Root directory containing skills (e.g., `skills/` or a single skill dir). */
  directory: string;
  /** Only scan files modified within this many days (0 = scan all). */
  recentDays?: number;
};

export function scanSkills(options: SkillScanOptions): ScanResult {
  const startedAt = Date.now();
  const findings: ScanFinding[] = [];
  const { directory, recentDays = 0 } = options;

  if (!fs.existsSync(directory)) {
    return {
      scanner: "skill-scanner",
      startedAt,
      completedAt: Date.now(),
      findings: [],
      error: `Directory not found: ${directory}`,
    };
  }

  const files = collectFiles(directory, MAX_FILES);
  const cutoff = recentDays > 0 ? Date.now() - recentDays * 24 * 60 * 60 * 1000 : 0;

  for (const filePath of files) {
    try {
      const stat = fs.statSync(filePath);

      // Skip files older than cutoff
      if (cutoff > 0 && stat.mtimeMs < cutoff) continue;

      // Skip oversized files
      if (stat.size > MAX_FILE_SIZE) continue;

      const lang = getLanguage(filePath);
      if (!lang) continue;

      const content = fs.readFileSync(filePath, "utf-8");
      const fileFindings = scanFileContent(filePath, content, lang);
      findings.push(...fileFindings);
    } catch {
      // Skip files we cannot read
    }
  }

  return {
    scanner: "skill-scanner",
    startedAt,
    completedAt: Date.now(),
    findings,
  };
}
