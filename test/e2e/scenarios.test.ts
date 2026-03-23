import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { run } from "../../src/index.js";
import { startServer, stopServer } from "./server.js";
import { Severity } from "../../src/checks/types.js";

let port: number;

beforeAll(async () => {
  port = await startServer();
});

afterAll(async () => {
  await stopServer();
});

function curlPipe(fixture: string): string {
  return `curl -fsSL http://127.0.0.1:${port}/${fixture} | bash`;
}

describe("e2e scenarios", { timeout: 15000 }, () => {
  describe("Scenario 1: GhostClaw Full Attack Chain", () => {
    it("detects multiple GhostClaw indicators and blocks", async () => {
      const result = await run(curlPipe("ghostclaw-full.sh"));

      expect(result.exitCode).toBe(2);

      const scriptResults = result.results.filter(
        (r) => r.check === "script-analysis"
      );
      expect(scriptResults.length).toBeGreaterThanOrEqual(3);

      // Should detect GhostClaw environment variables
      expect(
        scriptResults.some((r) => r.title.includes("GhostClaw environment"))
      ).toBe(true);

      // Should detect dscl credential validation
      expect(
        scriptResults.some((r) => r.title.includes("macOS credentials"))
      ).toBe(true);

      // Should detect System Preferences manipulation
      expect(
        scriptResults.some((r) => r.title.includes("System Preferences"))
      ).toBe(true);

      // Should detect persistence path
      expect(
        scriptResults.some((r) => r.title.includes("GhostClaw persistence"))
      ).toBe(true);

      // All GhostClaw-specific findings should be CRITICAL
      const ghostclawFindings = scriptResults.filter((r) =>
        r.title.includes("GhostClaw")
      );
      expect(
        ghostclawFindings.every((r) => r.severity === Severity.CRITICAL)
      ).toBe(true);
    });
  });

  describe("Scenario 2: Fake Password Dialog", () => {
    it("detects osascript dialog and terminal clearing", async () => {
      const result = await run(curlPipe("fake-dialog.sh"));

      expect(result.exitCode).toBe(2);

      const scriptResults = result.results.filter(
        (r) => r.check === "script-analysis"
      );

      // Should detect fake macOS dialog
      expect(
        scriptResults.some((r) => r.title.includes("fake macOS dialog"))
      ).toBe(true);

      // Should detect terminal clearing
      expect(
        scriptResults.some((r) => r.title.includes("terminal"))
      ).toBe(true);

      // Should detect disabled TLS
      expect(
        scriptResults.some((r) => r.title.includes("TLS"))
      ).toBe(true);
    });
  });

  describe("Scenario 3: Typosquatted npm Package", () => {
    it("detects 'expresss' as typosquat of 'express'", async () => {
      const result = await run("npm install expresss");

      expect(result.exitCode).toBe(2);
      expect(
        result.results.some(
          (r) =>
            r.check === "typosquat" && r.title.includes("express")
        )
      ).toBe(true);
    });

    it("detects 'lodassh' as typosquat of 'lodash'", async () => {
      const result = await run("npm install lodassh");

      expect(result.exitCode).toBe(2);
      expect(
        result.results.some(
          (r) =>
            r.check === "typosquat" && r.severity === Severity.HIGH
        )
      ).toBe(true);
    });
  });

  describe("Scenario 4: Reverse Shell", () => {
    it("detects /dev/tcp reverse shell pattern", async () => {
      const result = await run(curlPipe("reverse-shell.sh"));

      expect(result.exitCode).toBe(2);

      expect(
        result.results.some(
          (r) =>
            r.check === "script-analysis" &&
            r.severity === Severity.CRITICAL &&
            r.title.includes("reverse shell")
        )
      ).toBe(true);
    });
  });

  describe("Scenario 5: Base64-Obfuscated Payload", () => {
    it("detects base64 decoding in install script", async () => {
      const result = await run(curlPipe("obfuscated.sh"));

      expect(result.exitCode).toBe(2);

      expect(
        result.results.some(
          (r) =>
            r.check === "script-analysis" && r.title.includes("base64")
        )
      ).toBe(true);
    });
  });

  describe("Scenario 6: SSH Key Exfiltration", () => {
    it("detects SSH and cloud credential access", async () => {
      const result = await run(curlPipe("ssh-steal.sh"));

      expect(result.exitCode).toBe(2);

      const scriptResults = result.results.filter(
        (r) => r.check === "script-analysis"
      );

      // Should detect SSH/credential access
      expect(
        scriptResults.some((r) => r.title.includes("SSH keys"))
      ).toBe(true);

      // Should detect disabled TLS
      expect(
        scriptResults.some((r) => r.title.includes("TLS"))
      ).toBe(true);
    });
  });

  describe("Scenario 7: Persistence via LaunchAgent", () => {
    it("detects launchctl persistence and GhostClaw path", async () => {
      const result = await run(curlPipe("persistence.sh"));

      expect(result.exitCode).toBe(2);

      const scriptResults = result.results.filter(
        (r) => r.check === "script-analysis"
      );

      // Should detect persistence mechanism
      expect(
        scriptResults.some((r) => r.title.includes("persistence"))
      ).toBe(true);

      // Should detect launchctl
      expect(
        scriptResults.some(
          (r) =>
            r.severity === Severity.HIGH &&
            r.title.includes("persistence mechanism")
        )
      ).toBe(true);
    });
  });

  describe("Scenario 8: Crypto Wallet Theft", () => {
    it("detects cryptocurrency wallet targeting", async () => {
      const result = await run(curlPipe("crypto-wallet.sh"));

      expect(result.exitCode).toBe(2);

      expect(
        result.results.some(
          (r) =>
            r.check === "script-analysis" &&
            r.severity === Severity.CRITICAL &&
            r.title.includes("cryptocurrency")
        )
      ).toBe(true);
    });
  });

  describe("Scenario 9: Clean Install Script (negative control)", () => {
    it("passes a legitimate install script with no findings", async () => {
      const result = await run(curlPipe("clean-install.sh"));

      // Should have zero script-analysis findings
      const scriptResults = result.results.filter(
        (r) => r.check === "script-analysis"
      );
      expect(scriptResults).toHaveLength(0);
    });
  });

  describe("Scenario 10: Safe commands pass through", () => {
    it("git status passes immediately", async () => {
      const result = await run("git status");
      expect(result.exitCode).toBe(0);
      expect(result.results).toHaveLength(0);
    });

    it("npm install of legitimate package passes", async () => {
      const result = await run("npm install lodash");
      expect(result.exitCode).toBe(0);
    });

    it("brew install of a tool passes", async () => {
      const result = await run("brew install jq");
      expect(result.exitCode).toBe(0);
    });
  });
});
