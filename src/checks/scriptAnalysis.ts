import { Severity, type CheckResult } from "./types.js";

interface MaliciousPattern {
  regex: RegExp;
  title: string;
  severity: Severity;
  recommendation: string;
}

const MALICIOUS_PATTERNS: MaliciousPattern[] = [
  // Credential theft
  {
    regex: /\/etc\/passwd|\/etc\/shadow/gi,
    title: "Script accesses system credential files",
    severity: Severity.CRITICAL,
    recommendation: "This script reads sensitive system files. Do NOT run it.",
  },
  {
    regex: /~\/\.ssh\/|\.gnupg\/|\.aws\//gi,
    title: "Script accesses SSH keys or cloud credentials",
    severity: Severity.CRITICAL,
    recommendation:
      "This script accesses private keys or cloud credentials. Do NOT run it.",
  },
  {
    regex: /bitcoin|ethereum|wallet\.dat|\.solana|\.metamask/gi,
    title: "Script targets cryptocurrency wallets",
    severity: Severity.CRITICAL,
    recommendation:
      "This script targets crypto wallet data. Do NOT run it.",
  },

  // GhostClaw-specific patterns
  {
    regex: /dscl\s+\.\s+-authonly/gi,
    title: "Script validates macOS credentials (GhostClaw indicator)",
    severity: Severity.CRITICAL,
    recommendation:
      "This script uses dscl to validate your password — a known GhostClaw technique. Do NOT run it.",
  },
  {
    regex: /x-apple\.systempreferences:.*Privacy/gi,
    title: "Script manipulates macOS System Preferences",
    severity: Severity.CRITICAL,
    recommendation:
      "This script tries to open System Preferences to gain elevated access. Do NOT run it.",
  },
  {
    regex: /~\/\.cache\/\.npm_telemetry/gi,
    title: "Known GhostClaw persistence path detected",
    severity: Severity.CRITICAL,
    recommendation:
      "This path is used by GhostClaw malware for persistence. Do NOT run it.",
  },
  {
    regex: /NODE_CHANNEL|GHOST_PASSWORD/gi,
    title: "Known GhostClaw environment variables detected",
    severity: Severity.CRITICAL,
    recommendation:
      "These environment variables are associated with GhostClaw malware. Do NOT run it.",
  },

  // Reverse shells
  {
    regex: /\/dev\/tcp\/|nc\s+-e\s|ncat\s|mkfifo/gi,
    title: "Script contains reverse shell patterns",
    severity: Severity.CRITICAL,
    recommendation:
      "This script attempts to open a reverse shell connection. Do NOT run it.",
  },

  // Fake dialogs
  {
    regex: /osascript.*display\s+dialog/gi,
    title: "Script creates fake macOS dialog to steal credentials",
    severity: Severity.HIGH,
    recommendation:
      "This script shows fake system dialogs to trick you into entering your password.",
  },

  // Obfuscation
  {
    regex: /base64\s+(?:-d|--decode)|atob\s*\(/gi,
    title: "Script uses base64 decoding (possible obfuscation)",
    severity: Severity.HIGH,
    recommendation:
      "Base64 decoding in install scripts often hides malicious payloads. Review the decoded content.",
  },
  {
    regex: /curl\s+[^|]*-k|curl\s+[^|]*--insecure/gi,
    title: "Script disables TLS certificate validation",
    severity: Severity.HIGH,
    recommendation:
      "Disabling certificate validation allows man-in-the-middle attacks.",
  },

  // Persistence
  {
    regex: /crontab|launchctl\s+(load|submit|enable)|systemctl\s+enable/gi,
    title: "Script installs persistence mechanism",
    severity: Severity.HIGH,
    recommendation:
      "This script sets up automatic execution. Verify this is expected behavior.",
  },

  // Nested download-and-execute
  {
    regex:
      /(?:curl|wget)\s+[^|]*https?:\/\/[^\s]+[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh/gi,
    title: "Script contains nested download-and-execute chain",
    severity: Severity.HIGH,
    recommendation:
      "The script downloads and executes additional remote code. Review the nested URL.",
  },

  // Terminal clearing before credential theft
  {
    regex: /\\x1b\[2J|\\x1b\[3J|\\033\[2J/gi,
    title: "Script clears terminal (possible credential theft setup)",
    severity: Severity.HIGH,
    recommendation:
      "Terminal clearing before a prompt is a known technique to hide malicious activity.",
  },

  // Permission escalation
  {
    regex: /chmod\s+\+s|chmod\s+777/gi,
    title: "Script sets SUID/world-writable permissions",
    severity: Severity.MEDIUM,
    recommendation:
      "Setting SUID or world-writable permissions may indicate suspicious activity.",
  },

  // Dynamic code execution
  {
    regex: /\beval\s*\(/gi,
    title: "Script uses dynamic code execution (eval)",
    severity: Severity.MEDIUM,
    recommendation:
      "eval() in install scripts can hide malicious intent. Review what is being evaluated.",
  },
];

function checkObfuscationLevel(content: string): CheckResult | null {
  // Count hex/octal escape sequences
  const escapeMatches = content.match(/\\x[0-9a-fA-F]{2}|\\[0-7]{3}/g);
  if (!escapeMatches) return null;

  const ratio = escapeMatches.length / content.length;
  if (ratio > 0.3) {
    return {
      check: "script-analysis",
      severity: Severity.HIGH,
      title: "Script is heavily obfuscated",
      details: `${Math.round(ratio * 100)}% of the script consists of hex/octal escape sequences.`,
      recommendation:
        "Heavily obfuscated install scripts are a strong indicator of malicious intent.",
    };
  }
  return null;
}

function findLineNumber(content: string, index: number): number {
  return content.substring(0, index).split("\n").length;
}

function getContextLines(
  content: string,
  matchIndex: number,
  contextSize = 1
): string {
  const lines = content.split("\n");
  const lineNum = findLineNumber(content, matchIndex);
  const start = Math.max(0, lineNum - 1 - contextSize);
  const end = Math.min(lines.length, lineNum + contextSize);
  return lines
    .slice(start, end)
    .map((line, i) => `    ${start + i + 1}: ${line}`)
    .join("\n");
}

// Regex to find nested curl/wget piped to shell inside a script
const NESTED_CURL_REGEX =
  /(?:curl|wget)\s+[^|]*?(https?:\/\/[^\s"'<>|;)}\]]+)[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh/gi;

async function fetchScript(
  url: string,
  maxSizeKB: number
): Promise<{ content: string | null; error: CheckResult | null }> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);

    const response = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "LLM-Butcher/0.1.0" },
    });
    clearTimeout(timeout);

    if (!response.ok) {
      return {
        content: null,
        error: {
          check: "script-analysis",
          severity: Severity.MEDIUM,
          title: `Could not download script for analysis (HTTP ${response.status})`,
          details: `Failed to fetch ${url}`,
          recommendation:
            "Unable to pre-analyze the script. Proceed with caution.",
        },
      };
    }

    const content = await response.text();

    if (content.length > maxSizeKB * 1024) {
      return {
        content: null,
        error: {
          check: "script-analysis",
          severity: Severity.MEDIUM,
          title: "Script exceeds maximum analysis size",
          details: `Script is ${Math.round(content.length / 1024)}KB (max: ${maxSizeKB}KB).`,
          recommendation: "Large install scripts are unusual. Review manually.",
        },
      };
    }

    return { content, error: null };
  } catch (error) {
    return {
      content: null,
      error: {
        check: "script-analysis",
        severity: Severity.MEDIUM,
        title: "Could not download script for analysis",
        details: `Failed to fetch ${url}: ${error instanceof Error ? error.message : "unknown error"}`,
        recommendation:
          "Unable to pre-analyze the script. Proceed with caution.",
      },
    };
  }
}

function scanContent(content: string, source: string): CheckResult[] {
  const results: CheckResult[] = [];

  for (const pattern of MALICIOUS_PATTERNS) {
    pattern.regex.lastIndex = 0;
    const match = pattern.regex.exec(content);
    if (match) {
      const context = getContextLines(content, match.index);
      results.push({
        check: "script-analysis",
        severity: pattern.severity,
        title: pattern.title,
        details: `Match found in ${source}:\n${context}`,
        recommendation: pattern.recommendation,
      });
    }
  }

  const obfuscationResult = checkObfuscationLevel(content);
  if (obfuscationResult) {
    results.push(obfuscationResult);
  }

  return results;
}

const MAX_RECURSIVE_DEPTH = 3;

export async function analyzeScript(
  url: string,
  maxSizeKB: number
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const visited = new Set<string>();

  async function analyze(scriptUrl: string, depth: number): Promise<void> {
    if (depth > MAX_RECURSIVE_DEPTH) return;
    if (visited.has(scriptUrl)) return;
    visited.add(scriptUrl);

    const { content, error } = await fetchScript(scriptUrl, maxSizeKB);
    if (error) {
      results.push(error);
      return;
    }
    if (!content) return;

    const source = depth === 0 ? "downloaded script" : `nested script (depth ${depth}): ${scriptUrl}`;
    results.push(...scanContent(content, source));

    // Recursive fetch: find nested curl|sh patterns in the script
    NESTED_CURL_REGEX.lastIndex = 0;
    let nestedMatch: RegExpExecArray | null;
    const nestedUrls: string[] = [];
    while ((nestedMatch = NESTED_CURL_REGEX.exec(content)) !== null) {
      if (nestedMatch[1] && !visited.has(nestedMatch[1])) {
        nestedUrls.push(nestedMatch[1]);
      }
    }

    if (nestedUrls.length > 0) {
      results.push({
        check: "script-analysis",
        severity: Severity.HIGH,
        title: `Script downloads and executes ${nestedUrls.length} additional script(s)`,
        details: `Nested URLs found: ${nestedUrls.join(", ")}`,
        recommendation:
          "Multi-stage download chains are a common attack pattern. Each stage has been analyzed.",
      });

      for (const nestedUrl of nestedUrls) {
        await analyze(nestedUrl, depth + 1);
      }
    }
  }

  await analyze(url, 0);
  return results;
}
