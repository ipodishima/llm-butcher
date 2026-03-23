import { describe, it, expect, vi, beforeEach } from "vitest";
import { checkTyposquat } from "../../src/checks/typosquatDetection.js";
import { Severity } from "../../src/checks/types.js";
import { DEFAULT_CONFIG } from "../../src/config/defaults.js";

// Mock fetch for registry checks
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

describe("typosquatDetection", () => {
  beforeEach(() => {
    mockFetch.mockReset();
    // Default: package exists in registry
    mockFetch.mockResolvedValue({ status: 200 });
  });

  it("detects 1-character typosquat of lodash", async () => {
    const results = await checkTyposquat(
      [{ manager: "npm", name: "lodassh" }],
      DEFAULT_CONFIG
    );
    expect(results.some((r) => r.check === "typosquat" && r.severity === Severity.HIGH)).toBe(true);
    expect(results.some((r) => r.title.includes("lodash"))).toBe(true);
  });

  it("detects typosquat of express", async () => {
    const results = await checkTyposquat(
      [{ manager: "npm", name: "expresss" }],
      DEFAULT_CONFIG
    );
    expect(results.some((r) => r.title.includes("express"))).toBe(true);
  });

  it("detects typosquat of react", async () => {
    const results = await checkTyposquat(
      [{ manager: "npm", name: "reacct" }],
      DEFAULT_CONFIG
    );
    expect(results.some((r) => r.title.includes("react"))).toBe(true);
  });

  it("passes legitimate packages", async () => {
    const results = await checkTyposquat(
      [{ manager: "npm", name: "lodash" }],
      DEFAULT_CONFIG
    );
    // Should have no typosquat warnings (may have registry check if mocked as 404)
    expect(results.filter((r) => r.title.includes("typosquat"))).toHaveLength(0);
  });

  it("passes packages not close to any popular package", async () => {
    const results = await checkTyposquat(
      [{ manager: "npm", name: "my-unique-package-name-xyz" }],
      DEFAULT_CONFIG
    );
    expect(results.filter((r) => r.title.includes("typosquat"))).toHaveLength(0);
  });

  it("detects pip typosquats", async () => {
    const results = await checkTyposquat(
      [{ manager: "pip", name: "reqeusts" }],
      DEFAULT_CONFIG
    );
    expect(results.some((r) => r.title.includes("requests"))).toBe(true);
  });

  it("flags packages that don't exist in registry", async () => {
    mockFetch.mockResolvedValueOnce({ status: 404 });
    const results = await checkTyposquat(
      [{ manager: "npm", name: "xyznonexistent" }],
      DEFAULT_CONFIG
    );
    expect(results.some((r) => r.severity === Severity.CRITICAL)).toBe(true);
    expect(results.some((r) => r.title.includes("does not exist"))).toBe(true);
  });

  it("handles yarn manager as npm ecosystem", async () => {
    const results = await checkTyposquat(
      [{ manager: "yarn", name: "lodassh" }],
      DEFAULT_CONFIG
    );
    expect(results.some((r) => r.title.includes("lodash"))).toBe(true);
  });

  it("handles pnpm manager as npm ecosystem", async () => {
    const results = await checkTyposquat(
      [{ manager: "pnpm", name: "lodassh" }],
      DEFAULT_CONFIG
    );
    expect(results.some((r) => r.title.includes("lodash"))).toBe(true);
  });

  it("skips allowlisted packages", async () => {
    const config = {
      ...DEFAULT_CONFIG,
      allowlist: {
        ...DEFAULT_CONFIG.allowlist,
        packages: { npm: ["lodassh"], pip: [], brew: [] },
      },
    };
    const results = await checkTyposquat(
      [{ manager: "npm", name: "lodassh" }],
      config
    );
    expect(results).toHaveLength(0);
  });

  it("respects disabled config", async () => {
    const config = {
      ...DEFAULT_CONFIG,
      typosquat: { ...DEFAULT_CONFIG.typosquat, enabled: false },
    };
    const results = await checkTyposquat(
      [{ manager: "npm", name: "lodassh" }],
      config
    );
    expect(results).toHaveLength(0);
  });
});
