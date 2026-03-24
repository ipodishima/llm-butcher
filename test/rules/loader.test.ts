import { describe, it, expect, beforeEach } from "vitest";
import {
  loadAllRules,
  loadBuiltInRules,
  getCommandRules,
  getScriptRules,
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
    // Same reference because of caching
    expect(rules1).toBe(rules2);
  });
});
