# teardownpro/action

Checks a repository’s dependencies against its `teardown.yml` policy on every run, keeps signed
evidence of each decision and fails the build when the policy says so. It wraps the `teardown`
CLI (`@teardownpro/cli`) at the exact version released with it.

## Setup

### 1. Get a token

Tokens are issued by hand for now. Email hello@teardown.pro with the GitHub organization or
account the token is for. The token starts with `tdn_` and is shown once.

### 2. Add it as a secret

In the repository on GitHub, open **Settings**, then **Secrets and variables**, then **Actions**,
and choose **New repository secret**. Name it `TEARDOWN_TOKEN` and paste the token as its value.
For several repositories, add it once as an organization secret instead.

Never put the token in a workflow file, `teardown.yml` or anywhere else in the repository.

### 3. Add the workflow

Save this as `.github/workflows/teardown.yml`:

```yaml
name: Teardown
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: teardownpro/action@v1
        with:
          token: ${{ secrets.TEARDOWN_TOKEN }}
```

Pin both actions to a commit SHA if your organization requires it.

### 4. Choose a policy

The policy lives in `teardown.yml` at the repository root. Without one, the check uses the
exploit-first preset.

**Exploit-first** (the default) fails the build on packages in Fix first and on malicious
packages. Development dependencies are reported but don’t fail it. When Teardown can’t be
reached, the build passes and the evidence says the check didn’t run.

```yaml
version: 1
preset: exploit-first
```

**Regulated** adds a deadline to the rules above. Each Critical and High vulnerability must be
fixed within 30 days of its fix being released. Development dependencies count. When Teardown
can’t be reached, the build fails. Evidence must be signed, so unsigned evidence fails the build
too.

```yaml
version: 1
preset: regulated
```

Any field can be set over a preset. Unknown fields are an error, so a typo can’t weaken the
check.

```yaml
version: 1
preset: regulated
sla:
  days: 14
allowUnsignedEvidence: false
accepted:
  risks:
    - id: CVE-2025-64500
      package: symfony/http-foundation
      approver: Jane Doe
      reason: Behind the proxy that normalizes the path.
      compensatingControl: Proxy rule 12 rejects the malformed header.
      expires: 2027-01-31
```

An accepted risk needs an approver, a reason, a compensating control and an expiry date. It stops
applying on that date, and the regulated preset accepts at most 180 days.

To adopt the check on a repository that already has findings, run `teardown baseline` once,
commit `teardown-baseline.json` and set `baseline.enabled: true`. Findings in the baseline are
reported as warnings, and new ones still fail the build.

## What it sends

Only lockfiles, manifests, SBOMs and version files, by name (never code), with the policy and the
SHA-256 of each. The repository’s name, branch, commit and run stay in the job. They’re added to
the evidence file there.

## The evidence file

Each run writes `teardown-evidence.json` and uploads it as an artifact named
`teardown-evidence-<run>-<attempt>`, kept for 400 days (`evidence-retention-days`). It has three
parts.

- **`statement`**, signed by Teardown. The SHA-256 of each file checked, of the policy and of the
  baseline, every finding’s decision with its evidence and the rule that decided it, the ranking
  method, the date of every vulnerability source, the time and the key id.
- **`signature`**, an Ed25519 signature over the statement. When Teardown couldn’t sign,
  `signature` is null and `unsigned` gives the reason.
- **`fromJob`**, written by the CLI in the job and not signed. The repository, branch, commit, run
  URL, CLI version and fail mode.

The repository and commit sit outside the signed part, so the evidence proves which files got
which decisions and when, and `teardown verify` ties it to a commit by checking that commit’s files.

### Checking it with teardown verify

`teardown verify` checks the signature against the keys Teardown publishes at
https://teardown.pro/.well-known/teardown-evidence-keys.json. It then checks that the files, the
policy and the baseline in the working tree are the ones that were checked. Run it in a checkout
of the commit the evidence names, with the evidence file downloaded from the run’s artifacts:

```sh
git checkout <commit from fromJob.runner.commit>
npx @teardownpro/cli@0.1.1 verify teardown-evidence.json
```

It needs no token. It prints each check, exits 0 when everything matches and exits 1 naming
whatever doesn’t (a changed decision, a file that differs, an unknown key or a key outside its
dates). For a Gradle or Maven build, put the run’s `teardown-bom.cdx.json` next to the evidence
first. To verify without reaching teardown.pro, save the keys file and pass `--keys <file>`.

## Gradle and Maven: the sbom input

Teardown reads `gradle.lockfile` and CycloneDX or SPDX SBOMs directly, but not `pom.xml` or
`build.gradle`, which don’t pin every package. With `sbom: auto` (the default), when the
repository has a Gradle or Maven build and none of those files, the action runs
`npx --yes @cyclonedx/cdxgen@12.8.4 -t java -o teardown-bom.cdx.json`.

- **What cdxgen does:** it asks Gradle or Maven for the resolved dependency tree, so the build tool
  runs and downloads dependencies from the repositories the build names. It writes a CycloneDX SBOM
  to `teardown-bom.cdx.json`, and the check reads it: “exact from your build”. The SBOM is uploaded
  with the evidence.
- **When it runs:** only in that case. A repository with `gradle.lockfile` or an SBOM, or with no
  Gradle or Maven build, never runs it.
- **The version:** pinned exactly, at least two weeks old when pinned (12.8.4, 18 Aug 2026), the
  same cdxgen Teardown uses for its own SBOM.
- `sbom: off` never runs it. A Gradle or Maven build is then reported as not checked, and the
  regulated preset fails the run.

## Releases

This repository is public so npm can record provenance: each `@teardownpro/cli` version links to
the commit and workflow run that built it. `.github/workflows/release.yml` publishes on a `cli-v*`
tag with npm trusted publishing (GitHub’s OIDC token; there’s no npm token). Releases are staged:
the workflow runs `npm stage publish`, and a version goes live only once a maintainer approves it
on npm with two-factor authentication. The tree is written from Teardown’s source repository by
`scripts/export-cli.ts`.

## License

MIT, for the Action and the CLI. See `LICENSE`.
