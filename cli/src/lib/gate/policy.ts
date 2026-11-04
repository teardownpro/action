import { createHash } from 'node:crypto';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

/**
 * The CI gate's policy (docs/research/2026-10-27-ci-gate-spike.md, section 3): `teardown.yml` at
 * the repository root, a preset plus overrides. Unknown fields are an error, so a typo can't
 * quietly weaken a gate.
 */

export const GROUPS = ['fix-first', 'fix-next', 'low-risk'] as const;
export type Group = (typeof GROUPS)[number];
export const EVIDENCE = ['exploited', 'public-exploit', 'high-likelihood', 'no-known-exploit', 'no-data'] as const;
export const SEVERITIES = ['critical', 'high', 'moderate', 'low', 'unknown'] as const;

const IsoDay = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'a date as YYYY-MM-DD');

/** One accepted risk, reviewed in the same pull request as the code. */
export const AcceptedRisk = z
  .object({
    id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$/, 'a CVE or advisory id as Teardown shows it'),
    package: z.string().min(1).max(214).optional(),
    approver: z.string().min(3).max(120),
    reason: z.string().min(10).max(500),
    compensatingControl: z.string().min(5).max(500),
    expires: IsoDay,
    ticket: z.string().max(80).optional(),
  })
  .strict();
export type AcceptedRisk = z.infer<typeof AcceptedRisk>;

export const PolicySchema = z
  .object({
    version: z.literal(1),
    preset: z.enum(['exploit-first', 'regulated']),
    break: z
      .object({
        malicious: z.boolean(),
        groups: z.array(z.enum(GROUPS)).max(3),
        evidence: z.array(z.enum(EVIDENCE)).max(5),
      })
      .strict(),
    sla: z
      .object({
        enabled: z.boolean(),
        severities: z.array(z.enum(SEVERITIES)).max(5),
        days: z.number().int().min(1).max(365),
        unknownReleaseDate: z.enum(['advisory-published', 'break', 'warn']),
      })
      .strict(),
    scope: z.object({ devDependencies: z.enum(['count', 'warn']), runtimes: z.enum(['count', 'warn']) }).strict(),
    baseline: z.object({ enabled: z.boolean(), file: z.string().min(1).max(200) }).strict(),
    accepted: z.object({ maxDays: z.number().int().min(1).max(730), risks: z.array(z.unknown()).max(500) }).strict(),
    intel: z.object({ maxStaleDays: z.number().int().min(0).max(30) }).strict(),
    onError: z.enum(['fail-open', 'fail-closed']),
    /** Whether evidence Teardown couldn't sign still passes. Off in the regulated preset: unsigned evidence fails the run. */
    allowUnsignedEvidence: z.boolean(),
  })
  .strict();
export type Policy = z.infer<typeof PolicySchema>;

/** Breaks only on what's likely to be exploited: Fix first and malicious packages. The default. */
export const EXPLOIT_FIRST: Policy = {
  version: 1,
  preset: 'exploit-first',
  break: { malicious: true, groups: ['fix-first'], evidence: [] },
  sla: { enabled: false, severities: ['critical', 'high'], days: 30, unknownReleaseDate: 'advisory-published' },
  scope: { devDependencies: 'warn', runtimes: 'count' },
  baseline: { enabled: false, file: 'teardown-baseline.json' },
  accepted: { maxDays: 365, risks: [] },
  intel: { maxStaleDays: 3 },
  onError: 'fail-open',
  allowUnsignedEvidence: true,
};

/** Exploit-first plus Critical and High 30 days after the fix's release (PCI DSS 6.3.3); dev dependencies count; fails closed; evidence must be signed. */
export const REGULATED: Policy = {
  version: 1,
  preset: 'regulated',
  break: { malicious: true, groups: ['fix-first'], evidence: [] },
  sla: { enabled: true, severities: ['critical', 'high'], days: 30, unknownReleaseDate: 'advisory-published' },
  scope: { devDependencies: 'count', runtimes: 'count' },
  baseline: { enabled: false, file: 'teardown-baseline.json' },
  accepted: { maxDays: 180, risks: [] },
  intel: { maxStaleDays: 3 },
  onError: 'fail-closed',
  allowUnsignedEvidence: false,
};

export const PRESETS = { 'exploit-first': EXPLOIT_FIRST, regulated: REGULATED } as const;

export class PolicyError extends Error {}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** The preset, then the file's values over it, one level of sections deep. */
export function resolvePolicy(raw: unknown): Policy {
  if (raw === null || raw === undefined) return EXPLOIT_FIRST;
  if (!isObject(raw)) throw new PolicyError('The policy must be a mapping.');
  const presetName = raw.preset ?? 'exploit-first';
  if (presetName !== 'exploit-first' && presetName !== 'regulated') throw new PolicyError('preset must be exploit-first or regulated.');
  const base = PRESETS[presetName] as Record<string, unknown>;
  const merged: Record<string, unknown> = { ...base, preset: presetName };
  for (const [k, v] of Object.entries(raw)) {
    merged[k] = isObject(v) && isObject(base[k]) ? { ...(base[k] as Record<string, unknown>), ...v } : v;
  }
  const parsed = PolicySchema.safeParse(merged);
  if (!parsed.success) {
    const i = parsed.error.issues[0];
    throw new PolicyError(`${i.path.join('.') || 'policy'}: ${i.message}`);
  }
  return parsed.data;
}

/** teardown.yml's text, parsed and resolved. */
export function policyFromYaml(text: string): Policy {
  let raw: unknown;
  try {
    raw = parseYaml(text, { maxAliasCount: 10 });
  } catch (e) {
    throw new PolicyError(`teardown.yml isn’t valid YAML: ${(e as Error).message.split('\n')[0]}`);
  }
  return resolvePolicy(raw);
}

/** A stable SHA-256 of any JSON value (keys sorted), for the evidence. */
export function digest(value: unknown): string {
  return createHash('sha256').update(canonical(value), 'utf8').digest('hex');
}

export function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (isObject(value)) {
    return `{${Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}
