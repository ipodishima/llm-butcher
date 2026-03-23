import { describe, it, expect } from "vitest";
import { classifyCommand } from "../../src/parser/commandClassifier.js";

describe("commandClassifier", () => {
  describe("URL detection", () => {
    it("extracts URLs from curl commands", () => {
      const result = classifyCommand("curl -fsSL https://example.com/install.sh");
      expect(result.urls).toHaveLength(1);
      expect(result.urls[0].hostname).toBe("example.com");
    });

    it("extracts URLs from wget commands", () => {
      const result = classifyCommand("wget https://cdn.example.com/package.tar.gz");
      expect(result.urls).toHaveLength(1);
      expect(result.urls[0].hostname).toBe("cdn.example.com");
    });

    it("extracts multiple URLs", () => {
      const result = classifyCommand(
        "curl https://a.com/one && wget https://b.com/two"
      );
      expect(result.urls).toHaveLength(2);
    });

    it("returns no URLs for simple commands", () => {
      const result = classifyCommand("git status");
      expect(result.urls).toHaveLength(0);
    });
  });

  describe("pipe-to-shell detection", () => {
    it("detects curl piped to sh", () => {
      const result = classifyCommand(
        "curl -fsSL https://example.com/install.sh | sh"
      );
      expect(result.pipesToShell).toBe(true);
      expect(result.pipeToShellUrl).toBe("https://example.com/install.sh");
    });

    it("detects curl piped to bash", () => {
      const result = classifyCommand(
        "curl -fsSL https://example.com/install.sh | bash"
      );
      expect(result.pipesToShell).toBe(true);
    });

    it("detects curl piped to sudo bash", () => {
      const result = classifyCommand(
        "curl -fsSL https://example.com/install.sh | sudo bash"
      );
      expect(result.pipesToShell).toBe(true);
    });

    it("detects wget piped to sh", () => {
      const result = classifyCommand(
        "wget -qO- https://example.com/setup.sh | sh"
      );
      expect(result.pipesToShell).toBe(true);
    });

    it("does not flag non-pipe commands", () => {
      const result = classifyCommand("curl -o file.sh https://example.com/install.sh");
      expect(result.pipesToShell).toBe(false);
    });

    it("does not flag piping to non-shell", () => {
      const result = classifyCommand("curl https://example.com/data.json | jq .");
      expect(result.pipesToShell).toBe(false);
    });
  });

  describe("package install detection", () => {
    it("detects npm install", () => {
      const result = classifyCommand("npm install lodash");
      expect(result.packageInstalls).toHaveLength(1);
      expect(result.packageInstalls[0]).toEqual({
        manager: "npm",
        name: "lodash",
      });
    });

    it("detects npm i (shorthand)", () => {
      const result = classifyCommand("npm i express");
      expect(result.packageInstalls).toHaveLength(1);
      expect(result.packageInstalls[0].name).toBe("express");
    });

    it("detects npm install -g", () => {
      const result = classifyCommand("npm install -g typescript");
      expect(result.packageInstalls).toHaveLength(1);
      expect(result.packageInstalls[0].name).toBe("typescript");
    });

    it("detects yarn add", () => {
      const result = classifyCommand("yarn add react");
      expect(result.packageInstalls).toHaveLength(1);
      expect(result.packageInstalls[0]).toEqual({
        manager: "yarn",
        name: "react",
      });
    });

    it("detects pnpm add", () => {
      const result = classifyCommand("pnpm add vue");
      expect(result.packageInstalls).toHaveLength(1);
      expect(result.packageInstalls[0]).toEqual({
        manager: "pnpm",
        name: "vue",
      });
    });

    it("detects pip install", () => {
      const result = classifyCommand("pip install requests");
      expect(result.packageInstalls).toHaveLength(1);
      expect(result.packageInstalls[0]).toEqual({
        manager: "pip",
        name: "requests",
      });
    });

    it("detects pip3 install", () => {
      const result = classifyCommand("pip3 install numpy");
      expect(result.packageInstalls).toHaveLength(1);
      expect(result.packageInstalls[0].name).toBe("numpy");
    });

    it("detects brew install", () => {
      const result = classifyCommand("brew install jq");
      expect(result.packageInstalls).toHaveLength(1);
      expect(result.packageInstalls[0]).toEqual({
        manager: "brew",
        name: "jq",
      });
    });

    it("detects scoped npm packages", () => {
      const result = classifyCommand("npm install @types/node");
      expect(result.packageInstalls).toHaveLength(1);
      expect(result.packageInstalls[0].name).toBe("@types/node");
    });

    it("returns empty for non-install commands", () => {
      const result = classifyCommand("ls -la");
      expect(result.packageInstalls).toHaveLength(0);
    });
  });
});
