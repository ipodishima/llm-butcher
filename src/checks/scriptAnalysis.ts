import { Severity, type CheckResult } from "./types.js";
import type { CompiledRule } from "../rules/types.js";
import { loadAllRules, getScriptRules } from "../rules/loader.js";
import type { LoadRulesOptions } from "../rules/loader.js";

let scriptRules: CompiledRule[] | null = null;

export async function initScriptRules(
  options?: LoadRulesOptions
): Promise<void> {
  const allRules = await loadAllRules(options);
  scriptRules = getScriptRules(allRules);
}

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
  if (!scriptRules) return [];

  const results: CheckResult[] = [];

  for (const rule of scriptRules) {
    rule.regex.lastIndex = 0;
    const match = rule.regex.exec(content);
    if (match) {
      const context = getContextLines(content, match.index);
      results.push({
        check: "script-analysis",
        severity: rule.severity,
        title: rule.name,
        details: `Match found in ${source}:\n${context}`,
        recommendation: rule.recommendation,
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
