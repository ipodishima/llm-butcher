import { Severity, type CheckResult } from "./types.js";
import { analyzeCommand } from "./commandAnalysis.js";

/**
 * Parse simple shell variable assignments from a command string.
 * Handles: VAR=value, VAR="value", VAR='value'
 * Returns a map of variable name → resolved value.
 */
function parseVariableAssignments(command: string): Map<string, string> {
  const vars = new Map<string, string>();

  // Match VAR=value patterns (simple assignments)
  // Handles: a=curl, b="hello world", c='test'
  // Unquoted values stop at shell metacharacters (;|&<> and whitespace)
  const assignmentRegex =
    /\b([a-zA-Z_][a-zA-Z0-9_]*)=(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|([^\s;|&<>]+))/g;

  let match: RegExpExecArray | null;
  while ((match = assignmentRegex.exec(command)) !== null) {
    const name = match[1];
    // Priority: double-quoted, single-quoted, unquoted
    const value = match[2] ?? match[3] ?? match[4] ?? "";
    vars.set(name, value);
  }

  return vars;
}

/**
 * Resolve variable references ($VAR, ${VAR}) in a string using a variable map.
 * Also expands $HOME to ~ for pattern matching.
 */
function resolveVariables(
  command: string,
  vars: Map<string, string>
): string {
  let resolved = command;

  // Resolve ${VAR} references
  resolved = resolved.replace(/\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}/g, (_, name) => {
    return vars.get(name) ?? `\${${name}}`;
  });

  // Resolve $VAR references (must not be followed by more alphanumeric)
  resolved = resolved.replace(/\$([a-zA-Z_][a-zA-Z0-9_]*)/g, (full, name) => {
    return vars.get(name) ?? full;
  });

  // Expand $HOME to ~ for pattern matching
  resolved = resolved.replace(/\$HOME/g, "~");

  return resolved;
}

/**
 * Calculate a suspicion score based on shell obfuscation heuristics.
 */
interface HeuristicScore {
  score: number;
  reasons: string[];
}

function calculateHeuristicScore(command: string): HeuristicScore {
  const reasons: string[] = [];
  let score = 0;

  // Count single-letter variable assignments
  const singleLetterAssignments = command.match(
    /\b[a-zA-Z]=[^\s;|&]+/g
  );
  if (singleLetterAssignments && singleLetterAssignments.length >= 3) {
    score += singleLetterAssignments.length * 2;
    reasons.push(
      `${singleLetterAssignments.length} single-letter variable assignments`
    );
  }

  // Variables used to build command names (e.g., $a$b or ${a}${b} at start of command)
  if (/;\s*\$[a-zA-Z_]\$[a-zA-Z_]|\$\{[a-zA-Z_]\}\$\{[a-zA-Z_]\}/.test(command)) {
    score += 3;
    reasons.push("Variables concatenated to form command names");
  }

  // eval with variable interpolation
  if (/\beval\s+.*\$/.test(command)) {
    score += 5;
    reasons.push("eval with variable interpolation");
  }

  // Command substitution stored in variable
  if (/[a-zA-Z_][a-zA-Z0-9_]*=\$\(.*\)|[a-zA-Z_][a-zA-Z0-9_]*=`[^`]+`/.test(command)) {
    score += 2;
    reasons.push("Command substitution stored in variable");
  }

  // Heavy export usage followed by shell invocation
  const exportCount = (command.match(/\bexport\s+/g) || []).length;
  if (exportCount >= 3 && /;\s*(?:ba)?sh/.test(command)) {
    score += 2;
    reasons.push(`${exportCount} exports followed by shell invocation`);
  }

  return { score, reasons };
}

/**
 * Analyze a command for shell variable obfuscation and evasion.
 *
 * Phase A: Resolve variables and re-scan with existing patterns.
 * Phase B: Heuristic scoring for suspicious shell patterns.
 */
export function analyzeShellHeuristics(
  command: string,
  existingTitles: Set<string>
): CheckResult[] {
  const results: CheckResult[] = [];

  // Phase A: Variable resolution
  const vars = parseVariableAssignments(command);
  if (vars.size > 0) {
    const resolved = resolveVariables(command, vars);

    // Only re-scan if resolution actually changed the command
    if (resolved !== command) {
      const resolvedResults = analyzeCommand(resolved);

      // Only report findings that weren't already found in the original scan
      for (const result of resolvedResults) {
        if (!existingTitles.has(result.title)) {
          results.push({
            ...result,
            details:
              "Detected after resolving shell variables. " +
              `Original command uses variable obfuscation to hide: ${result.title}`,
          });
        }
      }
    }
  }

  // Phase B: Heuristic scoring
  const { score, reasons } = calculateHeuristicScore(command);
  if (score >= 7) {
    results.push({
      check: "script-analysis",
      severity: Severity.HIGH,
      title: "Suspicious shell variable obfuscation detected",
      details:
        `Obfuscation score: ${score}/10+. Indicators: ${reasons.join(", ")}. ` +
        "This command uses techniques commonly seen in attack obfuscation.",
      recommendation:
        "This command uses variable splitting/concatenation that may hide malicious intent. Review carefully before running.",
    });
  }

  return results;
}
