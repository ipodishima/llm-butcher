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
