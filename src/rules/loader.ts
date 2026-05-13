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

interface RuleCache {
  rules: CompiledRule[];
  optInPackIds: Set<string>;
}

let cache: RuleCache | null = null;

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

interface LoadedPack {
  rules: CompiledRule[];
  optIn: boolean;
  packId: string;
}

async function loadPackFromFile(filePath: string): Promise<LoadedPack | null> {
  try {
    const content = await readFile(filePath, "utf-8");
    const pack = yaml.load(content) as YamlRulePack;
    if (!pack || !pack.rules || !Array.isArray(pack.rules)) {
      return null;
    }
    return {
      packId: pack.id,
      optIn: pack.optIn === true,
      rules: pack.rules.map((rule) => compileRule(rule, pack.id)),
    };
  } catch {
    return null;
  }
}

async function loadPacksFromDirectory(dir: string): Promise<LoadedPack[]> {
  try {
    const files = await readdir(dir);
    const yamlFiles = files.filter(
      (f) => f.endsWith(".yaml") || f.endsWith(".yml")
    );
    const results = await Promise.all(
      yamlFiles.map((f) => loadPackFromFile(join(dir, f)))
    );
    return results.filter((p): p is LoadedPack => p !== null);
  } catch {
    return [];
  }
}

async function loadBuiltInPacks(): Promise<LoadedPack[]> {
  const packsDir = await findPacksDir();
  if (!packsDir) return [];
  return loadPacksFromDirectory(packsDir);
}

async function loadCustomPacks(): Promise<LoadedPack[]> {
  const globalDir = join(homedir(), ".llm-butcher", "rules");
  const projectDir = join(process.cwd(), ".llm-butcher", "rules");
  const [global, project] = await Promise.all([
    loadPacksFromDirectory(globalDir),
    loadPacksFromDirectory(projectDir),
  ]);
  return [...global, ...project];
}

/** Exported for tests that count rules across all packs. */
export async function loadBuiltInRules(): Promise<CompiledRule[]> {
  const packs = await loadBuiltInPacks();
  return packs.flatMap((p) => p.rules);
}

export async function loadCustomRules(): Promise<CompiledRule[]> {
  const packs = await loadCustomPacks();
  return packs.flatMap((p) => p.rules);
}

async function getOrBuildCache(): Promise<RuleCache> {
  if (cache) return cache;

  const [builtIn, custom] = await Promise.all([
    loadBuiltInPacks(),
    loadCustomPacks(),
  ]);

  const optInPackIds = new Set<string>();
  for (const pack of [...builtIn, ...custom]) {
    if (pack.optIn) optInPackIds.add(pack.packId);
  }

  // Deduplicate by rule id (custom rules override built-in)
  const ruleMap = new Map<string, CompiledRule>();
  for (const pack of builtIn) for (const rule of pack.rules) ruleMap.set(rule.id, rule);
  for (const pack of custom) for (const rule of pack.rules) ruleMap.set(rule.id, rule);

  cache = { rules: Array.from(ruleMap.values()), optInPackIds };
  return cache;
}

export interface LoadRulesOptions {
  disabledPacks?: string[];
  disabledRules?: string[];
  /** Pack ids of opt-in packs to enable. Opt-in packs are off by default. */
  enabledPacks?: string[];
}

export async function loadAllRules(
  options?: LoadRulesOptions
): Promise<CompiledRule[]> {
  const { rules, optInPackIds } = await getOrBuildCache();
  return filterRules(rules, optInPackIds, options);
}

function filterRules(
  rules: CompiledRule[],
  optInPackIds: Set<string>,
  options?: LoadRulesOptions
): CompiledRule[] {
  const enabled = options?.enabledPacks ?? [];

  return rules.filter((rule) => {
    if (optInPackIds.has(rule.packId) && !enabled.includes(rule.packId))
      return false;
    if (options?.disabledPacks?.includes(rule.packId)) return false;
    if (options?.disabledRules?.includes(rule.id)) return false;
    return true;
  });
}

/**
 * Return metadata for every loaded pack (including opt-in ones).
 * Used by the CLI policy list / status commands.
 */
export async function listPacks(): Promise<
  Array<{ id: string; optIn: boolean; ruleCount: number }>
> {
  const { rules, optInPackIds } = await getOrBuildCache();
  const byPack = new Map<string, number>();
  for (const rule of rules) {
    byPack.set(rule.packId, (byPack.get(rule.packId) ?? 0) + 1);
  }
  return Array.from(byPack.entries()).map(([id, ruleCount]) => ({
    id,
    ruleCount,
    optIn: optInPackIds.has(id),
  }));
}

export function getCommandRules(rules: CompiledRule[]): CompiledRule[] {
  return rules.filter((r) => r.scope === "command" || r.scope === "both");
}

export function getScriptRules(rules: CompiledRule[]): CompiledRule[] {
  return rules.filter((r) => r.scope === "script" || r.scope === "both");
}

/** Reset the cache (for testing) */
export function resetRuleCache(): void {
  cache = null;
}
