import { classifyCommand } from "./parser/commandClassifier.js";
import { analyzeCommand } from "./checks/commandAnalysis.js";
import { checkDomainReputation } from "./checks/domainReputation.js";
import { analyzeScript } from "./checks/scriptAnalysis.js";
import { checkTyposquat } from "./checks/typosquatDetection.js";
import { formatResults } from "./output/formatter.js";
import { loadConfig } from "./config/loader.js";
import { logAudit } from "./audit.js";
import type { CheckResult } from "./checks/types.js";

export interface HookInput {
  hook_event_name: string;
  tool_name: string;
  tool_input: {
    command: string;
    [key: string]: unknown;
  };
  session_id?: string;
}

export async function run(command: string): Promise<{
  output: string;
  exitCode: number;
  results: CheckResult[];
}> {
  const config = await loadConfig();
  const classification = classifyCommand(command);

  // Always scan the command itself for dangerous patterns
  const commandResults = analyzeCommand(command);

  // If no URLs or packages and no command-level findings, pass through
  if (
    classification.urls.length === 0 &&
    classification.packageInstalls.length === 0 &&
    commandResults.length === 0
  ) {
    return { output: "", exitCode: 0, results: [] };
  }

  const checks: Promise<CheckResult[]>[] = [];

  // Domain reputation (parallel)
  if (classification.urls.length > 0) {
    checks.push(checkDomainReputation(classification.urls, config));
  }

  // Script pre-analysis (when piping to shell)
  if (classification.pipesToShell && classification.pipeToShellUrl) {
    checks.push(
      analyzeScript(classification.pipeToShellUrl, config.scriptAnalysis.maxScriptSizeKB)
    );
  }

  // Typosquat detection (parallel)
  if (classification.packageInstalls.length > 0) {
    checks.push(checkTyposquat(classification.packageInstalls, config));
  }

  // Run all checks in parallel
  const settled = await Promise.allSettled(checks);

  const allResults: CheckResult[] = [...commandResults];
  for (const result of settled) {
    if (result.status === "fulfilled") {
      allResults.push(...result.value);
    }
  }

  // Deduplicate by title (command analysis and script analysis may catch the same thing)
  const seen = new Set<string>();
  const deduped = allResults.filter((r) => {
    if (seen.has(r.title)) return false;
    seen.add(r.title);
    return true;
  });

  const { output, exitCode } = formatResults(deduped, config);

  // Audit log (fire and forget — never blocks)
  logAudit(command, exitCode, deduped).catch(() => {});

  return { output, exitCode, results: deduped };
}
