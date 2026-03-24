import { readFile, readdir, access } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";
import yaml from "js-yaml";
import { Severity } from "../checks/types.js";
import type { YamlRulePack, CompiledRule } from "./types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Find the built-in packs directory. Handles both:
 * - Development (tsx): __dirname = src/rules/, packs at src/rules/packs/
 * - Bundled (dist): __dirname = dist/bin/ or dist/, packs at dist/rules/packs/
 * - Installed (node_modules): binary at dist/bin/, packs at dist/rules/packs/
 */
async function findPacksDir(): Promise<string | null> {
  const candidates = [
    join(__dirname, "packs"),                    // dev: src/rules/packs
    join(__dirname, "..", "rules", "packs"),      // bundled bin: dist/bin/../rules/packs
    join(__dirname, "rules", "packs"),            // bundled root: dist/rules/packs
  ];

  for (const dir of candidates) {
    try {
      await access(dir);
      return dir;
    } catch {
      // not found, try next
    }
  }
  return null;
}

const SEVERITY_MAP: Record<string, Severity> = {
  low: Severity.LOW,
  medium: Severity.MEDIUM,
  high: Severity.HIGH,
  critical: Severity.CRITICAL,
};

let cachedRules: CompiledRule[] | null = null;

function compileRule(
  rule: YamlRulePack["rules"][number],
  packId: string
): CompiledRule {
  let regex: RegExp;

  if (rule.match.mode === "regex") {
    const flags = rule.match.flags ?? "i";
    regex = new RegExp(rule.match.pattern!, flags);
  } else if (rule.match.mode === "keyword") {
    const escaped = rule.match.keywords![0].replace(
      /[.*+?^${}()|[\]\\]/g,
      "\\$&"
    );
    regex = new RegExp(escaped, "i");
  } else if (rule.match.mode === "keywords_any") {
    const escaped = rule.match
      .keywords!.map((k) => k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
      .join("|");
    regex = new RegExp(escaped, "i");
  } else if (rule.match.mode === "keywords_all") {
    // All keywords must be present — use lookahead for each
    const lookaheads = rule.match
      .keywords!.map(
        (k) => `(?=.*${k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`
      )
      .join("");
    regex = new RegExp(lookaheads, "is");
  } else {
    throw new Error(`Unknown match mode: ${rule.match.mode}`);
  }

  return {
    id: rule.id,
    name: rule.name,
    severity: SEVERITY_MAP[rule.severity] ?? Severity.MEDIUM,
    tags: rule.tags,
    scope: rule.scope,
    regex,
    recommendation: rule.recommendation,
    packId,
  };
}

async function loadPackFromFile(filePath: string): Promise<CompiledRule[]> {
  try {
    const content = await readFile(filePath, "utf-8");
    const pack = yaml.load(content) as YamlRulePack;
    if (!pack || !pack.rules || !Array.isArray(pack.rules)) {
      return [];
    }
    return pack.rules.map((rule) => compileRule(rule, pack.id));
  } catch {
    return [];
  }
}

async function loadPacksFromDirectory(dir: string): Promise<CompiledRule[]> {
  try {
    const files = await readdir(dir);
    const yamlFiles = files.filter(
      (f) => f.endsWith(".yaml") || f.endsWith(".yml")
    );
    const results = await Promise.all(
      yamlFiles.map((f) => loadPackFromFile(join(dir, f)))
    );
    return results.flat();
  } catch {
    return [];
  }
}

export async function loadBuiltInRules(): Promise<CompiledRule[]> {
  const packsDir = await findPacksDir();
  if (!packsDir) return [];
  return loadPacksFromDirectory(packsDir);
}

export async function loadCustomRules(): Promise<CompiledRule[]> {
  const rules: CompiledRule[] = [];

  // Global custom rules
  const globalDir = join(homedir(), ".llm-butcher", "rules");
  rules.push(...(await loadPacksFromDirectory(globalDir)));

  // Project custom rules
  const projectDir = join(process.cwd(), ".llm-butcher", "rules");
  rules.push(...(await loadPacksFromDirectory(projectDir)));

  return rules;
}

export interface LoadRulesOptions {
  disabledPacks?: string[];
  disabledRules?: string[];
}

export async function loadAllRules(
  options?: LoadRulesOptions
): Promise<CompiledRule[]> {
  if (cachedRules) {
    return filterRules(cachedRules, options);
  }

  const builtIn = await loadBuiltInRules();
  const custom = await loadCustomRules();

  // Deduplicate by ID (custom rules override built-in)
  const ruleMap = new Map<string, CompiledRule>();
  for (const rule of builtIn) {
    ruleMap.set(rule.id, rule);
  }
  for (const rule of custom) {
    ruleMap.set(rule.id, rule);
  }

  cachedRules = Array.from(ruleMap.values());
  return filterRules(cachedRules, options);
}

function filterRules(
  rules: CompiledRule[],
  options?: LoadRulesOptions
): CompiledRule[] {
  if (!options) return rules;

  return rules.filter((rule) => {
    if (options.disabledPacks?.includes(rule.packId)) return false;
    if (options.disabledRules?.includes(rule.id)) return false;
    return true;
  });
}

export function getCommandRules(rules: CompiledRule[]): CompiledRule[] {
  return rules.filter((r) => r.scope === "command" || r.scope === "both");
}

export function getScriptRules(rules: CompiledRule[]): CompiledRule[] {
  return rules.filter((r) => r.scope === "script" || r.scope === "both");
}

/** Reset the cache (for testing) */
export function resetRuleCache(): void {
  cachedRules = null;
}
