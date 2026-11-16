import type { Configuration } from "lint-staged";

const lintStagedConfig: Configuration = {
  "*.{cjs,cts,js,jsx,mjs,mts,ts,tsx}": (files) => [
    `pnpm nx affected:lint --fix --files=${files.join(",")}`,
    `pnpm nx format:write --files=${files.join(",")}`,
  ],
  "*.{css,html,json,md,scss,yaml,yml}": (files) => `pnpm nx format:write --files=${files.join(",")}`,
};

export default lintStagedConfig;
