import type { ViteUserConfig } from "vitest/config";
import { defineConfig } from "vitest/config";

const vitestConfig: ViteUserConfig = defineConfig({
  test: {
    coverage: {
      enabled: true,
      exclude: ["**/dist/**", "**/node_modules/**"],
      provider: "v8" as const,
      reportOnFailure: true,
      reporter: ["html"],
      reportsDirectory: "coverage",
    },
    globals: false,
    projects: [
      "**/vite.config.{mjs,js,ts,mts}",
      "**/vitest.config.mts",
      "!vitest.config.{mjs,js,ts,mts}",
      "!vite.config.{mjs,js,ts,mts}",
    ],
  },
});

export default vitestConfig;
