import type { ViteUserConfig } from "vitest/config";
import { defineConfig } from "vitest/config";

const vitestConfig: ViteUserConfig = defineConfig({
  test: {
    globals: false,
    projects: [
      "**/vite.config.{mjs,js,ts,mts}",
      "**/vitest.config.{mjs,js,ts,mts}",
      "!vitest.config.{mjs,js,ts,mts}",
      "!vite.config.{mjs,js,ts,mts}",
    ],
  },
});

export default vitestConfig;
