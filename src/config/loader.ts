import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import { DEFAULT_CONFIG, type ButcherConfig } from "./defaults.js";

const USER_CONFIG_DIR = join(homedir(), ".llm-butcher");
export const USER_CONFIG_PATH = join(USER_CONFIG_DIR, "config.json");

function deepMerge(target: any, source: any): any {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    if (
      source[key] &&
      typeof source[key] === "object" &&
      !Array.isArray(source[key])
    ) {
      result[key] = deepMerge(target[key] ?? {}, source[key]);
    } else {
      result[key] = source[key];
    }
  }
  return result;
}

export async function readJsonFile<T = unknown>(
  path: string
): Promise<T | null> {
  try {
    const content = await readFile(path, "utf-8");
    return JSON.parse(content) as T;
  } catch {
    return null;
  }
}

/** Read the user's global config verbatim, without merging defaults. */
export async function readUserConfig(): Promise<Partial<ButcherConfig>> {
  return (await readJsonFile<Partial<ButcherConfig>>(USER_CONFIG_PATH)) ?? {};
}

/** Write the user's global config verbatim, creating the directory if needed. */
export async function writeUserConfig(
  config: Partial<ButcherConfig>
): Promise<void> {
  await mkdir(dirname(USER_CONFIG_PATH), { recursive: true });
  await writeFile(
    USER_CONFIG_PATH,
    JSON.stringify(config, null, 2) + "\n",
    "utf-8"
  );
}

export async function loadConfig(): Promise<ButcherConfig> {
  let config: ButcherConfig = { ...DEFAULT_CONFIG };

  const globalConfig = await readJsonFile<Partial<ButcherConfig>>(
    USER_CONFIG_PATH
  );
  if (globalConfig) {
    config = deepMerge(config, globalConfig);
  }

  const projectConfig = await readJsonFile<Partial<ButcherConfig>>(
    join(process.cwd(), ".llm-butcher.json")
  );
  if (projectConfig) {
    config = deepMerge(config, projectConfig);
  }

  return config;
}
