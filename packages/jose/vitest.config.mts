import type { ViteUserConfigFnObject } from "vitest/config";
import { defineConfig } from "vitest/config";

const vitestConfig: ViteUserConfigFnObject = defineConfig(() => ({
  cacheDir: "../../node_modules/.vite/packages/jose",
  root: import.meta.dirname,
  test: {
    coverage: {
      provider: "v8" as const,
      reportsDirectory: "./test-output/vitest/coverage",
    },
    environment: "node",
    include: ["{src,tests}/**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}"],
    name: "jose",
    reporters: ["default"],
    watch: false,
  },
}));

export default vitestConfig;
