import { Severity, type CheckResult } from "../checks/types.js";
import type { ButcherConfig } from "../config/defaults.js";

const SEVERITY_ORDER: Record<Severity, number> = {
  [Severity.LOW]: 0,
  [Severity.MEDIUM]: 1,
  [Severity.HIGH]: 2,
  [Severity.CRITICAL]: 3,
};

const SEVERITY_LABELS: Record<Severity, string> = {
  [Severity.LOW]: "LOW",
  [Severity.MEDIUM]: "MEDIUM",
  [Severity.HIGH]: "HIGH",
  [Severity.CRITICAL]: "CRITICAL",
};

function meetsThreshold(severity: Severity, threshold: string): boolean {
  const thresholdLevel = SEVERITY_ORDER[threshold as Severity] ?? 2;
  return SEVERITY_ORDER[severity] >= thresholdLevel;
}

export function formatResults(
  results: CheckResult[],
  config: ButcherConfig
): { output: string; exitCode: number } {
  if (results.length === 0) {
    return { output: "", exitCode: 0 };
  }

  // Sort by severity (highest first)
  const sorted = [...results].sort(
    (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]
  );

  const shouldBlock = sorted.some((r) =>
    meetsThreshold(r.severity, config.severity.blockThreshold)
  );

  const blockCount = sorted.filter((r) =>
    meetsThreshold(r.severity, config.severity.blockThreshold)
  ).length;

  const lines: string[] = [];

  if (shouldBlock) {
    lines.push(
      `[LLM-Butcher] BLOCKED: ${blockCount} issue(s) exceed threshold\n`
    );
  } else {
    lines.push(`[LLM-Butcher] WARNING: ${results.length} issue(s) found\n`);
  }

  for (const result of sorted) {
    lines.push(
      `  ${SEVERITY_LABELS[result.severity]}: ${result.title}`
    );
    if (result.details) {
      lines.push(`    ${result.details.replace(/\n/g, "\n    ")}`);
    }
    lines.push(`    Recommendation: ${result.recommendation}`);
    lines.push("");
  }

  const exitCode = shouldBlock ? 2 : 1;

  return { output: lines.join("\n"), exitCode };
}
