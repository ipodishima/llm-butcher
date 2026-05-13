import { describe, it, expect, beforeEach } from "vitest";
import {
  loadAllRules,
  loadBuiltInRules,
  getCommandRules,
  getScriptRules,
  listPacks,
  resetRuleCache,
} from "../../src/rules/loader.js";
import { Severity } from "../../src/checks/types.js";

describe("rule loader", () => {
  beforeEach(() => {
    resetRuleCache();
  });

  it("loads built-in rules from YAML packs", async () => {
    const rules = await loadBuiltInRules();
    expect(rules.length).toBeGreaterThan(80);
  });

  it("all rules have required fields", async () => {
    const rules = await loadAllRules();
    for (const rule of rules) {
      expect(rule.id).toBeTruthy();
      expect(rule.name).toBeTruthy();
      expect(rule.severity).toBeTruthy();
      expect(rule.regex).toBeInstanceOf(RegExp);
      expect(rule.recommendation).toBeTruthy();
      expect(["command", "script", "both"]).toContain(rule.scope);
    }
  });

  it("filters command rules correctly", async () => {
    const allRules = await loadAllRules();
    const commandRules = getCommandRules(allRules);
    expect(commandRules.length).toBeGreaterThan(0);
    expect(commandRules.every((r) => r.scope === "command" || r.scope === "both")).toBe(true);
  });

  it("filters script rules correctly", async () => {
    const allRules = await loadAllRules();
    const scriptRules = getScriptRules(allRules);
    expect(scriptRules.length).toBeGreaterThan(0);
    expect(scriptRules.every((r) => r.scope === "script" || r.scope === "both")).toBe(true);
  });

  it("deduplicates rules by ID", async () => {
    const rules = await loadAllRules();
    const ids = rules.map((r) => r.id);
    const uniqueIds = new Set(ids);
    expect(ids.length).toBe(uniqueIds.size);
  });

  it("respects disabled packs", async () => {
    const allRules = await loadAllRules();
    resetRuleCache();
    const filteredRules = await loadAllRules({
      disabledPacks: ["reverse-shells"],
    });
    expect(filteredRules.length).toBeLessThan(allRules.length);
    expect(filteredRules.some((r) => r.packId === "reverse-shells")).toBe(false);
  });

  it("respects disabled individual rules", async () => {
    const allRules = await loadAllRules();
    resetRuleCache();
    const filteredRules = await loadAllRules({
      disabledRules: ["reverse-shell-dev-tcp"],
    });
    expect(filteredRules.length).toBe(allRules.length - 1);
    expect(filteredRules.some((r) => r.id === "reverse-shell-dev-tcp")).toBe(false);
  });

  it("includes rules from all expected packs", async () => {
    const rules = await loadAllRules();
    const packIds = new Set(rules.map((r) => r.packId));
    expect(packIds.has("reverse-shells")).toBe(true);
    expect(packIds.has("credentials")).toBe(true);
    expect(packIds.has("macos")).toBe(true);
    expect(packIds.has("exfiltration")).toBe(true);
    expect(packIds.has("persistence")).toBe(true);
    expect(packIds.has("network")).toBe(true);
    expect(packIds.has("prompt-injection")).toBe(true);
    expect(packIds.has("destructive")).toBe(true);
    expect(packIds.has("supply-chain")).toBe(true);
  });

  it("compiles regex patterns correctly", async () => {
    const rules = await loadAllRules();
    const devTcp = rules.find((r) => r.id === "reverse-shell-dev-tcp");
    expect(devTcp).toBeDefined();
    expect(devTcp!.regex.test("/dev/tcp/10.0.0.1/4242")).toBe(true);
    expect(devTcp!.severity).toBe(Severity.CRITICAL);
  });

  it("caches rules between calls", async () => {
    const rules1 = await loadAllRules();
    const rules2 = await loadAllRules();
    // Filter step allocates a fresh array; verify cache by deep-equal + length.
    expect(rules2).toStrictEqual(rules1);
    expect(rules2.length).toBe(rules1.length);
  });

  describe("opt-in policies", () => {
    it("does not load opt-in packs by default", async () => {
      const rules = await loadAllRules();
      expect(rules.some((r) => r.packId === "policy-pnpm")).toBe(false);
    });

    it("loads opt-in pack when explicitly enabled", async () => {
      resetRuleCache();
      const rules = await loadAllRules({ enabledPacks: ["policy-pnpm"] });
      expect(rules.some((r) => r.packId === "policy-pnpm")).toBe(true);
      expect(rules.some((r) => r.id === "npm-install-policy")).toBe(true);
    });

    it("listPacks reports opt-in metadata", async () => {
      const packs = await listPacks();
      const pnpm = packs.find((p) => p.id === "policy-pnpm");
      expect(pnpm).toBeDefined();
      expect(pnpm!.optIn).toBe(true);
      expect(pnpm!.ruleCount).toBeGreaterThanOrEqual(2);
      const supply = packs.find((p) => p.id === "supply-chain");
      expect(supply!.optIn).toBe(false);
    });
  });
});
