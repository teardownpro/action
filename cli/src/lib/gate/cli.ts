import { createHash } from 'node:crypto';
import { allowedFileName, MCP_MAX_FILES } from '../mcp/input';
import { EVIDENCE_FORMAT, KeysFile, KEYS_PATH, verifySignature } from './evidence';
import { canonical, digest, EXPLOIT_FIRST, PolicyError, policyFromYaml, PRESETS, resolvePolicy, type Policy } from './policy';

/**
 * `teardown check` and `teardown baseline` (docs/research/2026-10-27-ci-gate-spike.md): a thin CLI.
 * It finds the dependency files, sends them with the policy to /api/v1/check, prints the decisions,
 * writes the evidence and exits 0 (pass), 1 (fail) or 2 (couldn't run under fail-closed, or a
 * broken setup). Everything outside is injected (files, network, environment, clock), so tests run
 * it without either. The repository's name, branch and commit are added here, never sent.
 */

/** packages/cli/package.json's version (a test checks they match). */
export const CLI_VERSION = '0.1.0';
export const DEFAULT_API = 'https://teardown.pro';
/**
 * The cdxgen run for Gradle and Maven builds, pinned exactly (12.8.4, published 18 Aug 2026), the
 * version scripts/sbom-self.ts pins for Teardown's own SBOM.
 */
export const CDXGEN = '@cyclonedx/cdxgen@12.8.4';
export const CDXGEN_OUT = 'teardown-bom.cdx.json';

export interface CliIo {
  cwd: string;
  env: Record<string, string | undefined>;
  /** Root entries' names, and a directory's file names (empty when it's missing). */
  list(dir: string): string[];
  read(file: string): string | null;
  write(file: string, text: string): void;
  fetch: typeof fetch;
  out(line: string): void;
  err(line: string): void;
  now(): Date;
  /** Runs a command (cdxgen); resolves to its exit code. */
  exec?(cmd: string, args: string[]): Promise<number>;
}

interface Args {
  command: 'check' | 'baseline' | 'verify' | 'help' | 'version';
  /** verify: the evidence file. */
  file?: string;
  /** verify: a local copy of the published keys, instead of fetching them. */
  keys?: string;
  policy?: string;
  preset?: string;
  api: string;
  evidence: string;
  failMode?: 'fail-open' | 'fail-closed';
  /** auto: cdxgen only for a Gradle or Maven build with no gradle.lockfile or SBOM. off: never. */
  sbom: 'auto' | 'off';
  timeoutMs: number;
}

export class UsageError extends Error {}

export function parseArgs(argv: string[]): Args {
  const [command = 'help', ...rest] = argv;
  const a: Args = { command: 'help', api: DEFAULT_API, evidence: 'teardown-evidence.json', sbom: 'auto', timeoutMs: 120_000 };
  if (command === '--version' || command === 'version') return { ...a, command: 'version' };
  if (command === 'help' || command === '--help' || command === '-h') return a;
  if (command !== 'check' && command !== 'baseline' && command !== 'verify') throw new UsageError(`Unknown command “${command}”. Use teardown check, teardown baseline or teardown verify.`);
  a.command = command;
  for (let i = 0; i < rest.length; i++) {
    const flag = rest[i];
    if (command === 'verify' && !flag.startsWith('--')) {
      if (a.file) throw new UsageError('teardown verify takes one evidence file.');
      a.file = flag;
      continue;
    }
    const value = () => {
      const v = rest[++i];
      if (v === undefined || v.startsWith('--')) throw new UsageError(`${flag} needs a value.`);
      return v;
    };
    if (command === 'verify' && flag !== '--api' && flag !== '--keys' && flag !== '--timeout') throw new UsageError(`teardown verify takes --api, --keys and --timeout, not ${flag}.`);
    if (flag === '--keys') a.keys = value();
    else if (flag === '--policy') a.policy = value();
    else if (flag === '--preset') a.preset = value();
    else if (flag === '--api') a.api = value();
    else if (flag === '--evidence') a.evidence = value();
    else if (flag === '--fail-open') a.failMode = 'fail-open';
    else if (flag === '--fail-closed') a.failMode = 'fail-closed';
    else if (flag === '--sbom') {
      const v = value();
      if (v !== 'auto' && v !== 'off') throw new UsageError('--sbom is auto or off.');
      a.sbom = v;
    } else if (flag === '--timeout') {
      const s = Number(value());
      if (!Number.isInteger(s) || s < 5 || s > 600) throw new UsageError('--timeout is seconds, 5 to 600.');
      a.timeoutMs = s * 1000;
    } else throw new UsageError(`Unknown option ${flag}.`);
  }
  if (!/^https:\/\/[A-Za-z0-9.-]+(?::\d+)?$/.test(a.api) && !/^http:\/\/(?:localhost|127\.0\.0\.1)(?::\d+)?$/.test(a.api)) throw new UsageError('--api is an https origin, such as https://teardown.pro.');
  return a;
}

export const HELP = `teardown check     Check this repository’s dependencies against teardown.yml
teardown baseline  Write teardown-baseline.json from today’s findings
teardown verify [file]
                   Check an evidence file’s signature against Teardown’s published keys,
                   and its file, policy and baseline digests against this working tree

Options
  --policy <file>     The policy (default teardown.yml, else the exploit-first preset)
  --preset <name>     exploit-first or regulated, when there’s no policy file
  --evidence <file>   Where the evidence goes (default teardown-evidence.json)
  --fail-open         Pass when Teardown can’t be reached (exploit-first’s default)
  --fail-closed       Fail when Teardown can’t be reached (regulated’s default)
  --sbom <mode>       auto (default) runs ${CDXGEN} for a Gradle or Maven build
                      with no gradle.lockfile or SBOM; off never runs it
  --api <origin>      Teardown’s address (default ${DEFAULT_API})
  --timeout <s>       Seconds to wait for Teardown (default 120)
  --keys <file>       verify: a saved copy of ${DEFAULT_API}${KEYS_PATH}

The token comes from TEARDOWN_TOKEN. Only lockfiles, manifests, SBOMs and version files are sent.`;

/** The policy: --policy, else teardown.yml, else --preset or exploit-first. */
export function loadPolicy(io: CliIo, a: Pick<Args, 'policy' | 'preset'>): { policy: Policy; source: string; file: string | null; preset: string | null; fileSha256: string | null } {
  const file = a.policy ?? 'teardown.yml';
  const text = io.read(file);
  if (text === null) {
    if (a.policy) throw new UsageError(`${a.policy} wasn’t found.`);
    if (a.preset && !(a.preset in PRESETS)) throw new UsageError('--preset is exploit-first or regulated.');
    return { policy: a.preset ? resolvePolicy({ version: 1, preset: a.preset }) : EXPLOIT_FIRST, source: a.preset ? `preset ${a.preset}` : 'preset exploit-first (no teardown.yml)', file: null, preset: a.preset ?? null, fileSha256: null };
  }
  if (a.preset) throw new UsageError(`Set the preset in ${file}, not with --preset.`);
  try {
    return { policy: policyFromYaml(text), source: file, file, preset: null, fileSha256: sha256(text) };
  } catch (e) {
    throw new UsageError(e instanceof PolicyError ? `${file}: ${e.message}` : `${file} couldn’t be read.`);
  }
}

const sha256 = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');

/** Gradle and Maven build files: their packages need an SBOM (or gradle.lockfile) to be exact. */
const JVM_BUILD = /^(?:pom\.xml|build\.gradle(?:\.kts)?|settings\.gradle(?:\.kts)?)$/;

/** The dependency files at the root (plus requirements/ and workflows), by the MCP allowlist. */
export function discoverFiles(io: CliIo): { files: Array<{ name: string; text: string }>; jvmWithoutSbom: boolean } {
  const names = [
    ...io.list('.'),
    ...io.list('requirements').map((n) => `requirements/${n}`),
    ...io.list('.github/workflows').map((n) => `.github/workflows/${n}`),
  ].filter(allowedFileName);
  // Our own evidence and baseline aren't inputs, whatever their names.
  const picked = [...new Set(names)].filter((n) => n !== 'teardown-evidence.json' && n !== 'teardown-baseline.json').sort();
  const files = picked.flatMap((name) => {
    const text = io.read(name);
    return text === null ? [] : [{ name, text }];
  });
  const root = io.list('.');
  const jvm = root.some((n) => JVM_BUILD.test(n));
  const hasJvmData = files.some((f) => f.name === 'gradle.lockfile' || /\.(?:cdx|spdx)\.json$|^s?bom\.json$/i.test(f.name));
  return { files, jvmWithoutSbom: jvm && !hasJvmData };
}

/** Where the run is, from the CI's environment: GitHub Actions, GitLab CI, or nothing. Stays on the runner. */
export function runnerContext(env: CliIo['env']) {
  if (env.GITHUB_ACTIONS === 'true') {
    const server = env.GITHUB_SERVER_URL ?? 'https://github.com';
    return {
      ci: 'github-actions',
      repository: env.GITHUB_REPOSITORY ?? null,
      commit: env.GITHUB_SHA ?? null,
      // A pull request's branch is GITHUB_HEAD_REF; a push's is GITHUB_REF_NAME.
      branch: env.GITHUB_HEAD_REF || env.GITHUB_REF_NAME || null,
      ref: env.GITHUB_REF ?? null,
      runUrl: env.GITHUB_REPOSITORY && env.GITHUB_RUN_ID ? `${server}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}${env.GITHUB_RUN_ATTEMPT ? `/attempts/${env.GITHUB_RUN_ATTEMPT}` : ''}` : null,
      actor: env.GITHUB_ACTOR ?? null,
    };
  }
  if (env.GITLAB_CI === 'true') {
    return { ci: 'gitlab-ci', repository: env.CI_PROJECT_PATH ?? null, commit: env.CI_COMMIT_SHA ?? null, branch: env.CI_MERGE_REQUEST_SOURCE_BRANCH_NAME || env.CI_COMMIT_BRANCH || null, ref: env.CI_COMMIT_REF_NAME ?? null, runUrl: env.CI_JOB_URL ?? null, actor: env.GITLAB_USER_LOGIN ?? null };
  }
  return { ci: env.CI === 'true' ? 'other' : 'local', repository: null, commit: null, branch: null, ref: null, runUrl: null, actor: null };
}

type Outcome = { kind: 'ok'; body: Record<string, unknown> } | { kind: 'unavailable'; reason: string } | { kind: 'refused'; status: number; reason: string };

async function call(io: CliIo, a: Args, token: string, body: unknown): Promise<Outcome> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), a.timeoutMs);
  try {
    const res = await io.fetch(`${a.api}/api/v1/check`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}`, 'user-agent': `teardown-cli/${CLI_VERSION}` },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    const text = await res.text();
    let json: Record<string, unknown> = {};
    try {
      json = JSON.parse(text) as Record<string, unknown>;
    } catch {
      /* not JSON: the status decides */
    }
    const reason = typeof json.error === 'string' ? json.error.slice(0, 300) : `HTTP ${res.status}`;
    if (res.ok) return { kind: 'ok', body: json };
    // The server or its limits: the check couldn't run. Anything else is the setup's fault.
    if (res.status >= 500 || res.status === 429 || res.status === 408) return { kind: 'unavailable', reason: `${reason} (HTTP ${res.status})` };
    return { kind: 'refused', status: res.status, reason };
  } catch (e) {
    return { kind: 'unavailable', reason: ctrl.signal.aborted ? `No answer within ${a.timeoutMs / 1000}s.` : `Teardown couldn’t be reached (${(e as Error).name}).` };
  } finally {
    clearTimeout(timer);
  }
}

/** Runs a command and returns its exit code. */
export async function main(argv: string[], io: CliIo): Promise<number> {
  let a: Args;
  try {
    a = parseArgs(argv);
  } catch (e) {
    io.err(e instanceof UsageError ? e.message : String(e));
    return 2;
  }
  if (a.command === 'help') {
    io.out(HELP);
    return 0;
  }
  if (a.command === 'version') {
    io.out(CLI_VERSION);
    return 0;
  }
  if (a.command === 'verify') return verifyEvidence(io, a);
  const token = io.env.TEARDOWN_TOKEN?.trim() ?? '';
  if (!/^tdn_[A-Za-z0-9_-]{43}$/.test(token)) {
    io.err('TEARDOWN_TOKEN isn’t set to a Teardown token (tdn_…). In GitHub Actions, pass it from a secret.');
    return 2;
  }
  let loaded;
  try {
    loaded = loadPolicy(io, a);
  } catch (e) {
    io.err(e instanceof UsageError ? e.message : String(e));
    return 2;
  }
  const { policy } = loaded;
  const failMode = a.failMode ?? policy.onError;

  // Gradle and Maven: an SBOM from this build (cdxgen), unless one is committed.
  let found = discoverFiles(io);
  if (found.jvmWithoutSbom) {
    if (a.sbom === 'auto' && io.exec) {
      io.out(`Generating a CycloneDX SBOM for the Gradle or Maven build with ${CDXGEN}…`);
      const code = await io.exec('npx', ['--yes', CDXGEN, '-t', 'java', '-o', CDXGEN_OUT]);
      if (code !== 0) {
        io.err(`cdxgen exited with ${code}, so the Gradle or Maven packages can’t be checked.`);
        return 2;
      }
      found = discoverFiles(io);
    } else {
      io.err(`A Gradle or Maven build with no SBOM or gradle.lockfile: its packages can’t be checked exactly. Run with --sbom auto, or commit gradle.lockfile.`);
      if (policy.preset === 'regulated') return 2;
    }
  }
  const files = found.files;
  if (files.length === 0) {
    io.err('No lockfiles, manifests or SBOMs found here.');
    return 2;
  }
  if (files.length > MCP_MAX_FILES) {
    io.err(`${files.length} dependency files found; Teardown reads ${MCP_MAX_FILES} at most in one check.`);
    return 2;
  }

  if (a.command === 'baseline') {
    const r = await call(io, a, token, { mode: 'baseline', files, policy, digests: { files: files.map((f) => ({ name: f.name, sha256: sha256(f.text) })), policy: digest(policy), baseline: null } });
    if (r.kind !== 'ok') {
      io.err(`The baseline couldn’t be made: ${r.reason}`);
      return 2;
    }
    io.write(policy.baseline.file, `${JSON.stringify(r.body.baseline, null, 2)}\n`);
    const n = (r.body.baseline as { findings: unknown[] }).findings.length;
    io.out(`Wrote ${policy.baseline.file} with ${n} finding${n === 1 ? '' : 's'}. Commit it, and set baseline.enabled in teardown.yml.`);
    return 0;
  }

  let baseline: unknown[] | undefined;
  let baselineSha256: string | null = null;
  if (policy.baseline.enabled) {
    const text = io.read(policy.baseline.file);
    if (text === null) {
      io.err(`baseline.enabled is on but ${policy.baseline.file} wasn’t found. Run teardown baseline first.`);
      return 2;
    }
    baseline = baselineEntries(text) ?? undefined;
    if (!baseline) {
      io.err(`${policy.baseline.file} isn’t a Teardown baseline.`);
      return 2;
    }
    baselineSha256 = sha256(text);
  }

  const started = io.now();
  const runner = runnerContext(io.env);
  const local = { cli: CLI_VERSION, policySource: loaded.source, policyFile: loaded.file, preset: loaded.preset, policyFileSha256: loaded.fileSha256, baselineFileSha256: baselineSha256, failMode, startedAt: started.toISOString() };
  const sentPolicy = { ...policy, onError: failMode };
  // What's sent, hashed here; the server recomputes these from what it receives and signs them.
  const digests = { files: files.map((f) => ({ name: f.name, sha256: sha256(f.text) })), policy: digest(sentPolicy), baseline: baseline ? digest(baseline) : null };
  const r = await call(io, a, token, { files, policy: sentPolicy, ...(baseline ? { baseline } : {}), digests });

  const finish = (out: { result: string; exitCode: number; reason?: string; statement?: unknown; signature?: unknown; unsigned?: string | null }) => {
    const body = {
      format: EVIDENCE_FORMAT,
      // The run's outcome, as the job acted on it. For a check that ran, the same result as the signed statement's.
      result: out.result,
      exitCode: out.exitCode,
      ...(out.reason ? { reason: out.reason } : {}),
      // Signed by Teardown: what the server knows about the run (teardown verify checks it).
      statement: out.statement ?? null,
      signature: out.signature ?? null,
      unsigned: out.statement ? (out.unsigned ?? null) : 'The check didn’t run, so nothing was signed.',
      // From the job, not signed: where the run happened, added here on the runner and never sent.
      fromJob: { note: FROM_JOB_NOTE, runner, local: { ...local, finishedAt: io.now().toISOString() }, ...(out.statement ? {} : { inputs: digests.files }) },
    };
    io.write(a.evidence, `${JSON.stringify({ ...body, sha256: digest(body) }, null, 2)}\n`);
    return out.exitCode;
  };

  if (r.kind === 'refused') {
    io.err(`Teardown refused the check (${r.status}): ${r.reason}`);
    return finish({ result: 'not-run', exitCode: 2, reason: r.reason });
  }
  if (r.kind === 'unavailable') {
    const code = failMode === 'fail-closed' ? 2 : 0;
    io.err(`The check didn’t run: ${r.reason} ${failMode === 'fail-closed' ? 'Failing the build (fail-closed).' : 'Passing the build (fail-open); the evidence says it didn’t run.'}`);
    return finish({ result: 'not-run', exitCode: code, reason: r.reason });
  }

  const statement = r.body.statement as StatementView;
  // The server checked exactly these files, this policy and this baseline.
  if (!statement || canonical(statement.digests) !== canonical(digests)) {
    io.err('The files, policy or baseline Teardown checked don’t match the ones sent. Not trusting this result.');
    return finish({ result: 'not-run', exitCode: 2, reason: 'digest mismatch' });
  }
  const signature = r.body.signature ?? null;
  const unsigned = typeof r.body.unsigned === 'string' ? r.body.unsigned : null;
  let exitCode = r.body.exitCode === 0 ? 0 : 1;
  let result = statement.result === 'pass' ? 'pass' : 'fail';
  // The server fails unsigned evidence under a policy that forbids it; checked here as well, so such a pass is never written.
  if (!signature && !policy.allowUnsignedEvidence) {
    exitCode = 1;
    result = 'fail';
  }
  report(io, statement, policy, result, signature ? null : (unsigned ?? 'no signature.'));
  return finish({ result, exitCode, statement, signature, unsigned });
}

const FROM_JOB_NOTE = 'From the CI job, not signed by Teardown: the CLI added this on the runner, and the server never saw it.';

/** The parts of the signed statement the CLI reads. */
interface StatementView {
  result: string;
  digests: { files: Array<{ name: string; sha256: string }>; policy: string; baseline: string | null };
  decisions: Array<Record<string, unknown>>;
  counts: Record<string, number>;
  intelStale: { stale: boolean; detail: string };
  acceptedRisks: Array<{ status: string; id: string; detail: string }>;
  policy: { resolved: Policy };
  signing: { kid?: string; unsigned?: string };
  decidedAt: string;
}

/** teardown-baseline.json's entries as the check sends them (package and id), or null when it isn't a baseline. */
export function baselineEntries(text: string): Array<{ package: string; id: string }> | null {
  try {
    const findings = (JSON.parse(text) as { findings: unknown }).findings;
    if (!Array.isArray(findings)) return null;
    return findings.map((f) => {
      const { package: p, id } = f as { package: string; id: string };
      return { package: p, id };
    });
  } catch {
    return null;
  }
}

async function fetchKeys(io: CliIo, a: Args): Promise<KeysFile | string> {
  let text: string | null;
  let where: string;
  if (a.keys) {
    where = a.keys;
    text = io.read(a.keys);
    if (text === null) return `${a.keys} wasn’t found.`;
  } else {
    where = `${a.api}${KEYS_PATH}`;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), Math.min(a.timeoutMs, 30_000));
    try {
      const res = await io.fetch(where, { headers: { 'user-agent': `teardown-cli/${CLI_VERSION}` }, signal: ctrl.signal, redirect: 'error' });
      if (!res.ok) return `${where} answered HTTP ${res.status}.`;
      text = await res.text();
    } catch (e) {
      return `${where} couldn’t be reached (${(e as Error).name}).`;
    } finally {
      clearTimeout(timer);
    }
  }
  try {
    return KeysFile.parse(JSON.parse(text));
  } catch {
    return `${where} isn’t a Teardown keys file.`;
  }
}

/**
 * `teardown verify`: the signature against the published keys (never keys from the evidence itself),
 * then the signed digests against this working tree. Exit 0 when everything matches, 1 on any
 * mismatch (each one named), 2 when it couldn't verify (no file, no keys).
 */
async function verifyEvidence(io: CliIo, a: Args): Promise<number> {
  const file = a.file ?? 'teardown-evidence.json';
  const text = io.read(file);
  if (text === null) {
    io.err(`${file} wasn’t found.`);
    return 2;
  }
  let e: { format?: unknown; result?: unknown; statement?: StatementView | null; signature?: unknown; unsigned?: unknown; fromJob?: { local?: { policyFile?: unknown; preset?: unknown; failMode?: unknown } } };
  try {
    e = JSON.parse(text);
  } catch {
    io.err(`${file} isn’t JSON.`);
    return 2;
  }
  if (e.format !== EVIDENCE_FORMAT) {
    io.err(`${file} isn’t Teardown evidence in the ${EVIDENCE_FORMAT} format.`);
    return 2;
  }
  const s = e.statement;
  if (!s) {
    io.out(`✗ statement: the check didn’t run, so nothing was signed.`);
    io.out('Not verified.');
    return 1;
  }
  const keys = await fetchKeys(io, a);
  if (typeof keys === 'string') {
    io.err(`The published keys couldn’t be read: ${keys}`);
    return 2;
  }

  const failures: string[] = [];
  const passed: string[] = [];
  if (!e.signature) failures.push(`signature: the evidence is unsigned (${typeof e.unsigned === 'string' ? e.unsigned : 'no reason given'}).`);
  else {
    const sig = verifySignature(s, e.signature, keys);
    if (sig.ok) passed.push(`signature: valid, key ${(e.signature as { kid: string }).kid}, signed ${s.decidedAt}.`);
    failures.push(...sig.failures);
  }

  // The signed file digests against the working tree, and no dependency file left out.
  const checked = new Set<string>();
  for (const f of s.digests?.files ?? []) {
    checked.add(f.name);
    const t = io.read(f.name);
    if (t === null) failures.push(`file: ${f.name} was checked but isn’t in this working tree.`);
    else if (sha256(t) !== f.sha256) failures.push(`file: ${f.name} differs from the one Teardown checked.`);
    else passed.push(`file: ${f.name} matches.`);
  }
  for (const f of discoverFiles(io).files) if (!checked.has(f.name)) failures.push(`file: ${f.name} is in this working tree but wasn’t checked.`);

  // The policy: the job's policy file (or preset) here, with the job's fail mode, hashed as the CLI sent it.
  const local = e.fromJob?.local ?? {};
  try {
    const loaded = loadPolicy(io, { policy: typeof local.policyFile === 'string' ? local.policyFile : undefined, preset: typeof local.preset === 'string' ? local.preset : undefined });
    if (local.failMode !== 'fail-open' && local.failMode !== 'fail-closed') failures.push('policy: the job’s record has no fail mode, so the policy can’t be recomputed.');
    else if (digest({ ...loaded.policy, onError: local.failMode }) !== s.digests?.policy) failures.push(`policy: ${loaded.source} in this working tree isn’t the policy Teardown checked.`);
    else passed.push(`policy: ${loaded.source} matches.`);
  } catch (err) {
    failures.push(`policy: ${err instanceof Error ? err.message : 'couldn’t be read'}`);
  }

  // The baseline, when one was sent.
  if (s.digests?.baseline) {
    const name = s.policy?.resolved?.baseline?.file ?? 'teardown-baseline.json';
    const t = io.read(name);
    const entries = t === null ? null : baselineEntries(t);
    if (!entries) failures.push(`baseline: ${name} isn’t in this working tree.`);
    else if (digest(entries) !== s.digests.baseline) failures.push(`baseline: ${name} differs from the one Teardown checked.`);
    else passed.push(`baseline: ${name} matches.`);
  }

  if (e.result !== s.result) failures.push(`result: the job recorded ${String(e.result)}, and the signed result is ${s.result}.`);

  for (const p of passed) io.out(`✓ ${p}`);
  for (const f of failures) io.out(`✗ ${f}`);
  io.out(failures.length ? `Not verified: ${failures.length} problem${failures.length === 1 ? '' : 's'}.` : `Verified: signed by Teardown (${s.signing?.kid}), result ${s.result}.`);
  return failures.length ? 1 : 0;
}

function report(io: CliIo, e: StatementView, policy: Policy, result: string, unsigned: string | null) {
  const breaks = e.decisions.filter((d) => d.status === 'break');
  for (const d of breaks) io.out(`✗ ${d.package} ${d.version}  ${d.id}  ${d.note}`);
  for (const r of e.acceptedRisks.filter((x) => x.status === 'expired' || x.status === 'invalid' || x.status === 'too-long')) io.out(`! Accepted risk ${r.id || '(no id)'} doesn’t apply: ${r.detail}`);
  if (e.intelStale.stale) io.out(`! Intel: ${e.intelStale.detail}`);
  if (unsigned !== null) io.out(policy.allowUnsignedEvidence ? `! Evidence unsigned: ${unsigned}` : `✗ Evidence unsigned: ${unsigned} The policy needs signed evidence (allowUnsignedEvidence: false).`);
  const c = e.counts;
  io.out(`${result === 'pass' ? 'Pass' : 'Fail'} (${policy.preset}): ${c.break} breaking, ${c.warn} warnings, ${c.accepted} accepted, ${c.unconfirmed} unconfirmed (never breaking).`);
}
