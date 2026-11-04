# @teardownpro/cli

`teardown check` sends a repository’s lockfiles, manifests, SBOMs and version files with its
`teardown.yml` policy to Teardown, prints each decision, writes `teardown-evidence.json` and exits
0 (pass), 1 (fail) or 2 (couldn’t run under fail-closed, or a broken setup). Only dependency files
are sent, never code. The repository’s name, branch, commit and run stay on the machine.

```sh
TEARDOWN_TOKEN=tdn_… npx @teardownpro/cli check
npx @teardownpro/cli baseline
npx @teardownpro/cli verify teardown-evidence.json
```

- **`check`** reads `teardown.yml`, or uses the exploit-first preset when there’s none.
- **`baseline`** writes `teardown-baseline.json` from today’s findings.
- **`verify`** checks the evidence’s Ed25519 signature against the keys Teardown publishes at
  https://teardown.pro/.well-known/teardown-evidence-keys.json, then checks the files, policy and
  baseline in the working tree against the signed digests. It needs no token and exits 1 naming
  any mismatch.

In GitHub Actions, use `teardownpro/action`, which runs this CLI at its exact version. Setup,
the presets and the evidence file are described in that repository’s README. Tokens are issued
by hand for now: email hello@teardown.pro.

MIT licensed.
