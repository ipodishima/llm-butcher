import { run } from "../src/index.js";
import { parseHookInput } from "../src/parser/inputParser.js";
import { loadAllRules, listPacks, resetRuleCache } from "../src/rules/loader.js";
import { policyNameFromPackId } from "../src/rules/types.js";
import {
  readUserConfig,
  writeUserConfig,
  USER_CONFIG_PATH,
} from "../src/config/loader.js";
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

const args = process.argv.slice(2);
const subcommand = args[0];

if (subcommand === "policy") {
  policyCommand(args.slice(1)).catch((error) => {
    process.stderr.write(`Error: ${error instanceof Error ? error.message : "unknown"}\n`);
    process.exit(1);
  });
} else if (process.argv.includes("--list-rules")) {
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

const POLICY_HELP = `Usage:
  llm-butcher policy list              Show all available policies and their state.
  llm-butcher policy enable <name>     Enable a policy (writes ~/.llm-butcher/config.json).
  llm-butcher policy disable <name>    Disable a policy.
  llm-butcher policy status <name>     Show whether a policy is enabled.

Available policies are discovered from rule packs marked \`optIn: true\`. The
pack id \`policy-<name>\` maps to the friendly name \`<name>\`.

Examples:
  llm-butcher policy enable pnpm       Block npm install / npx, recommend pnpm.
`;

interface PolicyContext {
  nameArg: string | undefined;
  policies: Map<string, { packId: string; ruleCount: number }>;
}

const policyHandlers: Record<string, (ctx: PolicyContext) => Promise<number>> = {
  list: handleList,
  enable: (ctx) => handleSet(ctx, true),
  disable: (ctx) => handleSet(ctx, false),
  status: handleStatus,
};

async function policyCommand(rest: string[]): Promise<void> {
  resetRuleCache();
  const [action, nameArg] = rest;

  if (!action || action === "help" || action === "--help" || action === "-h") {
    process.stdout.write(POLICY_HELP);
    process.exit(0);
  }

  const packs = await listPacks();
  const policies = new Map<string, { packId: string; ruleCount: number }>();
  for (const pack of packs) {
    if (!pack.optIn) continue;
    const friendly = policyNameFromPackId(pack.id) ?? pack.id;
    policies.set(friendly, { packId: pack.id, ruleCount: pack.ruleCount });
  }

  const handler = policyHandlers[action];
  if (!handler) {
    process.stderr.write(POLICY_HELP);
    process.exit(1);
  }
  process.exit(await handler({ nameArg, policies }));
}

async function handleList({ policies }: PolicyContext): Promise<number> {
  if (policies.size === 0) {
    process.stdout.write("No opt-in policies available.\n");
    return 0;
  }
  const config = await readUserConfig();
  const enabledMap = config.policies ?? {};
  process.stdout.write("\nLLM-Butcher policies (opt-in):\n\n");
  for (const [name, { packId, ruleCount }] of policies) {
    const state = enabledMap[name] === true ? "ENABLED " : "disabled";
    process.stdout.write(
      `  [${state}] ${name.padEnd(12)} ${ruleCount} rule(s)  (pack: ${packId})\n`
    );
  }
  process.stdout.write(
    `\nEnable with: llm-butcher policy enable <name>\nConfig: ${USER_CONFIG_PATH}\n`
  );
  return 0;
}

function requirePolicyName(
  ctx: PolicyContext
): { name: string } | null {
  if (!ctx.nameArg) {
    process.stderr.write(`Missing policy name. Try: llm-butcher policy list\n`);
    return null;
  }
  if (!ctx.policies.has(ctx.nameArg)) {
    const known = Array.from(ctx.policies.keys()).join(", ") || "(none)";
    process.stderr.write(
      `Unknown policy "${ctx.nameArg}". Known policies: ${known}\n`
    );
    return null;
  }
  return { name: ctx.nameArg };
}

async function handleStatus(ctx: PolicyContext): Promise<number> {
  const resolved = requirePolicyName(ctx);
  if (!resolved) return 1;
  const config = await readUserConfig();
  const enabled = config.policies?.[resolved.name] === true;
  process.stdout.write(
    `Policy "${resolved.name}" is ${enabled ? "ENABLED" : "disabled"}.\n`
  );
  return 0;
}

async function handleSet(ctx: PolicyContext, enable: boolean): Promise<number> {
  const resolved = requirePolicyName(ctx);
  if (!resolved) return 1;
  const config = await readUserConfig();
  config.policies = { ...(config.policies ?? {}), [resolved.name]: enable };
  await writeUserConfig(config);
  process.stdout.write(
    `Policy "${resolved.name}" ${enable ? "enabled" : "disabled"}. Wrote ${USER_CONFIG_PATH}.\n`
  );
  return 0;
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
