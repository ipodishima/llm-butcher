import { run, type HookInput } from "../src/index.js";

async function main(): Promise<void> {
  // Read stdin
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  const rawInput = Buffer.concat(chunks).toString("utf-8").trim();

  if (!rawInput) {
    process.exit(0);
  }

  let hookInput: HookInput;
  try {
    hookInput = JSON.parse(rawInput);
  } catch {
    // JSON parse failure could indicate a bypass attempt via malformed input.
    // Warn but don't block — the hook contract requires valid JSON from Claude Code,
    // so this likely means a non-standard integration.
    process.stderr.write(
      "[LLM-Butcher] WARNING: Could not parse hook input as JSON. " +
      "If this is a Claude Code hook, the input format may have changed. " +
      "LLM-Butcher cannot analyze this command.\n"
    );
    process.exit(1); // Exit 1 = warn (non-blocking)
  }

  // Only handle Bash tool calls
  if (hookInput.tool_name !== "Bash") {
    process.exit(0);
  }

  const command = hookInput.tool_input?.command;
  if (!command || typeof command !== "string") {
    process.exit(0);
  }

  const { output, exitCode } = await run(command);

  if (output) {
    process.stderr.write(output);
  }

  process.exit(exitCode);
}

main().catch((error) => {
  process.stderr.write(
    `[LLM-Butcher] Unexpected error: ${error instanceof Error ? error.message : "unknown"}\n`
  );
  process.exit(0); // Don't block on unexpected errors
});
