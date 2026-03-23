import { defineConfig } from "tsup";

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
