import { run } from "../src/index.js";
import { parseHookInput } from "../src/parser/inputParser.js";
import { loadAllRules } from "../src/rules/loader.js";
import { toSarif, toJson } from "../src/output/sarif.js";

type OutputFormat = "text" | "sarif" | "json";

function getOutputFormat(): OutputFormat {
  const idx = process.argv.indexOf("--output");
  if (idx !== -1 && process.argv[idx + 1]) {
    const format = process.argv[idx + 1] as OutputFormat;
    if (["text", "sarif", "json"].includes(format)) return format;
  }
  if (process.argv.includes("--sarif")) return "sarif";
  return "text";
}

// Handle CLI flags before reading stdin
if (process.argv.includes("--list-rules")) {
  listRules().catch((error) => {
    process.stderr.write(`Error: ${error instanceof Error ? error.message : "unknown"}\n`);
    process.exit(1);
  });
} else {
  main().catch((error) => {
    process.stderr.write(
      `[LLM-Butcher] Unexpected error: ${error instanceof Error ? error.message : "unknown"}\n`
    );
    process.exit(0); // Don't block on unexpected errors
  });
}

async function listRules(): Promise<void> {
  const rules = await loadAllRules();

  const packs = new Map<string, typeof rules>();
  for (const rule of rules) {
    const existing = packs.get(rule.packId) ?? [];
    existing.push(rule);
    packs.set(rule.packId, existing);
  }

  console.log(`\nLLM-Butcher Rules — ${rules.length} rules in ${packs.size} packs\n`);

  for (const [packId, packRules] of packs) {
    console.log(`  ${packId} (${packRules.length} rules)`);
    for (const rule of packRules) {
      const severity = rule.severity.toUpperCase().padEnd(8);
      const scope = rule.scope.padEnd(7);
      console.log(`    ${severity} [${scope}] ${rule.id}: ${rule.name}`);
    }
    console.log("");
  }

  process.exit(0);
}

function emitResults(
  command: string,
  output: string,
  exitCode: number,
  results: Parameters<typeof toSarif>[0],
  format: OutputFormat
): void {
  if (format === "sarif") {
    const sarif = toSarif(results, command);
    process.stdout.write(JSON.stringify(sarif, null, 2) + "\n");
  } else if (format === "json") {
    process.stdout.write(toJson(results, exitCode) + "\n");
  } else {
    // text format — write to stderr (default hook behavior)
    if (output) {
      process.stderr.write(output);
    }
  }
}

async function main(): Promise<void> {
  const format = getOutputFormat();

  // Read stdin
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  const rawInput = Buffer.concat(chunks).toString("utf-8").trim();

  if (!rawInput) {
    process.exit(0);
  }

  const parsed = parseHookInput(rawInput);

  // Full JSON parsed successfully — normal flow
  if (parsed.parseMethod === "json" && parsed.hookInput) {
    // Only handle Bash tool calls
    if (parsed.hookInput.tool_name !== "Bash") {
      process.exit(0);
    }

    const command = parsed.hookInput.tool_input?.command;
    if (!command || typeof command !== "string") {
      process.exit(0);
    }

    const { output, exitCode, results } = await run(command);
    emitResults(command, output, exitCode, results, format);
    process.exit(exitCode);
  }

  // Fallback: command extracted via regex or raw input
  if (parsed.rawCommand) {
    process.stderr.write(
      `[LLM-Butcher] WARNING: JSON parse failed, extracted command via ${parsed.parseMethod} fallback. ` +
        "Analysis will proceed but some metadata may be missing.\n"
    );

    const { output, exitCode, results } = await run(parsed.rawCommand);
    emitResults(parsed.rawCommand, output, exitCode, results, format);
    process.exit(exitCode);
  }

  // Nothing extractable — block as potential bypass attempt
  process.stderr.write(
    "[LLM-Butcher] BLOCKED: Could not parse hook input and no command could be extracted. " +
      "This may indicate a bypass attempt via malformed input.\n"
  );
  process.exit(2);
}
