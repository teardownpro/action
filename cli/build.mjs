// Bundles the CLI into one file with no install-time dependencies (scripts/build-cli.ts in the source repository).
import { build } from 'esbuild';

await build({
  entryPoints: ['packages/cli/src/bin.ts'],
  outfile: 'dist/teardown.mjs',
  bundle: true,
  platform: 'node',
  target: 'node20',
  format: 'esm',
  banner: { js: '#!/usr/bin/env node\nimport { createRequire as __cr } from "node:module"; const require = __cr(import.meta.url);' },
  legalComments: 'external',
  logLevel: 'warning',
});
