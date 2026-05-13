import type { Severity } from "../checks/types.js";

export interface YamlRule {
  id: string;
  name: string;
  severity: "low" | "medium" | "high" | "critical";
  tags: string[];
  scope: "command" | "script" | "both";
  match: {
    mode: "regex" | "keyword" | "keywords_any" | "keywords_all";
    pattern?: string;
    keywords?: string[];
    flags?: string; // regex flags, default "i"
  };
  recommendation: string;
}

export interface YamlRulePack {
  id: string;
  name: string;
  description: string;
  /**
   * Opt-in packs are skipped by default. Users enable them via
   * `llm-butcher policy enable <name>` or by adding the pack id to
   * `rules.enabledPacks` in their config.
   */
  optIn?: boolean;
  rules: YamlRule[];
}

export interface CompiledRule {
  id: string;
  name: string;
  severity: Severity;
  tags: string[];
  scope: "command" | "script" | "both";
  regex: RegExp;
  recommendation: string;
  packId: string;
}

/**
 * Friendly policy name (e.g. `pnpm`) maps to the pack id `policy-<name>`.
 * Single source of truth for the prefix used in CLI args, config keys, and
 * pack ids.
 */
export const POLICY_PACK_PREFIX = "policy-";
export const policyPackId = (name: string) => `${POLICY_PACK_PREFIX}${name}`;
export const policyNameFromPackId = (packId: string) =>
  packId.startsWith(POLICY_PACK_PREFIX)
    ? packId.slice(POLICY_PACK_PREFIX.length)
    : null;
