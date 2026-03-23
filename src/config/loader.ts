import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import { DEFAULT_CONFIG, type ButcherConfig } from "./defaults.js";

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

async function readJsonFile(path: string): Promise<Record<string, any> | null> {
  try {
    const content = await readFile(path, "utf-8");
    return JSON.parse(content);
  } catch {
    return null;
  }
}

export async function loadConfig(): Promise<ButcherConfig> {
  let config: ButcherConfig = { ...DEFAULT_CONFIG };

  // Global config
  const globalConfig = await readJsonFile(
    join(homedir(), ".llm-butcher", "config.json")
  );
  if (globalConfig) {
    config = deepMerge(config, globalConfig);
  }

  // Project config
  const projectConfig = await readJsonFile(
    join(process.cwd(), ".llm-butcher.json")
  );
  if (projectConfig) {
    config = deepMerge(config, projectConfig);
  }

  return config;
}
