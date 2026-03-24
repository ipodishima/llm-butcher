import type { CheckResult } from "./types.js";
import type { CompiledRule } from "../rules/types.js";
import { loadAllRules, getCommandRules } from "../rules/loader.js";
import type { LoadRulesOptions } from "../rules/loader.js";

let commandRules: CompiledRule[] | null = null;

export async function initCommandRules(
  options?: LoadRulesOptions
): Promise<void> {
  const allRules = await loadAllRules(options);
  commandRules = getCommandRules(allRules);
}

export function analyzeCommand(command: string): CheckResult[] {
  if (!commandRules) {
    // Rules not loaded yet — this shouldn't happen in normal flow
    // but return empty to avoid crashes
    return [];
  }

  const results: CheckResult[] = [];

  for (const rule of commandRules) {
    rule.regex.lastIndex = 0;
    if (rule.regex.test(command)) {
      results.push({
        check: "script-analysis",
        severity: rule.severity,
        title: rule.name,
        details: "Dangerous pattern detected in command.",
        recommendation: rule.recommendation,
      });
    }
  }

  return results;
}
