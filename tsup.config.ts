import { defineConfig } from "tsup";
import { cpSync } from "node:fs";

export default defineConfig([
  {
    entry: ["bin/llm-butcher.ts"],
    format: ["esm"],
    target: "node18",
    outDir: "dist/bin",
    clean: true,
    splitting: false,
    sourcemap: true,
    banner: {
      js: "#!/usr/bin/env node",
    },
    onSuccess: async () => {
      // Copy YAML rule packs to dist so they're available at runtime
      cpSync("src/rules/packs", "dist/rules/packs", { recursive: true });
      // Copy data files
      cpSync("src/data", "dist/data", { recursive: true });
    },
  },
  {
    entry: ["src/index.ts"],
    format: ["esm"],
    target: "node18",
    outDir: "dist",
    clean: false,
    splitting: false,
    sourcemap: true,
    dts: true,
  },
]);
