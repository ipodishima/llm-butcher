import type { HookInput } from "../index.js";

export interface ParseResult {
  hookInput: HookInput | null;
  rawCommand: string | null;
  parseMethod: "json" | "regex" | "raw" | "none";
}

/**
 * Extract command string from partial/broken JSON using regex.
 * Handles cases where quotes or special chars inside the command break JSON.parse.
 */
function extractCommandViaRegex(raw: string): string | null {
  // Try to find "command": "..." pattern, handling escaped quotes
  // Match "command" : "..." where the value may contain escaped quotes
  const match = raw.match(/"command"\s*:\s*"((?:[^"\\]|\\.)*)"/);
  if (match?.[1]) {
    // Unescape the extracted string
    return match[1]
      .replace(/\\"/g, '"')
      .replace(/\\\\/g, "\\")
      .replace(/\\n/g, "\n")
      .replace(/\\t/g, "\t");
  }

  // Try single-quoted variant (non-standard but defensive)
  const singleQuoteMatch = raw.match(/"command"\s*:\s*'((?:[^'\\]|\\.)*)'/);
  if (singleQuoteMatch?.[1]) {
    return singleQuoteMatch[1];
  }

  return null;
}

/**
 * Multi-strategy parser for Claude Code hook input.
 *
 * Strategy 1: Full JSON.parse (normal case)
 * Strategy 2: Regex extraction of "command" field from broken JSON
 * Strategy 3: Treat raw input as the command itself (last resort)
 */
export function parseHookInput(rawInput: string): ParseResult {
  // Strategy 1: Standard JSON parse
  try {
    const parsed = JSON.parse(rawInput) as HookInput;
    if (
      parsed &&
      typeof parsed === "object" &&
      typeof parsed.tool_name === "string"
    ) {
      return {
        hookInput: parsed,
        rawCommand: parsed.tool_input?.command ?? null,
        parseMethod: "json",
      };
    }
  } catch {
    // JSON parse failed — try fallback strategies
  }

  // Strategy 2: Regex extraction from partial/broken JSON
  const regexCommand = extractCommandViaRegex(rawInput);
  if (regexCommand) {
    return {
      hookInput: null,
      rawCommand: regexCommand,
      parseMethod: "regex",
    };
  }

  // Strategy 3: If input looks like it could be a shell command (not JSON-like),
  // treat it as the raw command. This catches cases where something pipes a bare
  // command to us instead of the expected JSON envelope.
  const trimmed = rawInput.trim();
  if (trimmed.length > 0 && !trimmed.startsWith("{")) {
    return {
      hookInput: null,
      rawCommand: trimmed,
      parseMethod: "raw",
    };
  }

  // Nothing extractable — input is broken JSON with no recoverable command
  return {
    hookInput: null,
    rawCommand: null,
    parseMethod: "none",
  };
}
