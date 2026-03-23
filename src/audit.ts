import { appendFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import { createHash } from "node:crypto";
import type { CheckResult } from "./checks/types.js";

const AUDIT_DIR = join(homedir(), ".llm-butcher");
const AUDIT_PATH = join(AUDIT_DIR, "audit.log");

interface AuditEntry {
  timestamp: string;
  command: string;
  commandHash: string;
  verdict: "allowed" | "warned" | "blocked";
  findingCount: number;
  findings: { severity: string; title: string }[];
}

export async function logAudit(
  command: string,
  exitCode: number,
  results: CheckResult[]
): Promise<void> {
  try {
    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      command:
        command.length > 200 ? command.substring(0, 200) + "..." : command,
      commandHash: createHash("sha256").update(command).digest("hex").substring(0, 16),
      verdict:
        exitCode === 0 ? "allowed" : exitCode === 1 ? "warned" : "blocked",
      findingCount: results.length,
      findings: results.map((r) => ({
        severity: r.severity,
        title: r.title,
      })),
    };

    await mkdir(AUDIT_DIR, { recursive: true });
    await appendFile(AUDIT_PATH, JSON.stringify(entry) + "\n", "utf-8");
  } catch {
    // Never block on audit logging failures
  }
}
