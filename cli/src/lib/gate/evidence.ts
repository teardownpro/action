import { createHash, createPrivateKey, createPublicKey, sign, verify, type KeyObject } from 'node:crypto';
import { z } from 'zod';
import { canonical } from './policy';

/**
 * Signed evidence for the CI gate (Ed25519). The server signs what it knows (the statement: the
 * file, policy and baseline digests, every decision with its evidence, the method, every intel
 * source's date, the time and the key id) and the CLI adds what only the job knows (repository,
 * branch, commit, run) outside the signed part. The two are bound by the file digests: the CLI
 * sends them, the server recomputes them from what it received and refuses a mismatch, and
 * `teardown verify` checks them against the working tree.
 *
 * Pure apart from node:crypto, and part of the CLI's exported source, so the CLI verifies with
 * exactly the code the server signs with. No key is read here: the server passes one in.
 */

export const STATEMENT_TYPE = 'teardown.evidence.statement';
export const STATEMENT_VERSION = 1;
export const EVIDENCE_FORMAT = 'teardown-evidence/2';
export const ALG = 'Ed25519';
/** Where the public keys are published, under the API's origin. */
export const KEYS_PATH = '/.well-known/teardown-evidence-keys.json';

/** The exact bytes that are signed: the statement's canonical JSON (keys sorted, no whitespace), UTF-8. */
export const signedBytes = (statement: unknown) => Buffer.from(canonical(statement), 'utf8');

/** The key id: `ev-ed25519-` and the first 16 hex characters of the SHA-256 of the raw 32-byte public key. */
export function keyIdOf(publicKey: KeyObject): string {
  return `ev-ed25519-${createHash('sha256').update(rawPublicKey(publicKey)).digest('hex').slice(0, 16)}`;
}

/** The 32 raw bytes of an Ed25519 public key (the last 32 bytes of its SPKI DER). */
export function rawPublicKey(publicKey: KeyObject): Buffer {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return der.subarray(der.length - 32);
}

/** The SPKI DER prefix of an Ed25519 public key; the raw 32 bytes follow it. */
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** A published key's base64url raw bytes as a KeyObject, or null when it isn't an Ed25519 key. */
export function publicKeyFrom(base64url: string): KeyObject | null {
  const raw = Buffer.from(base64url, 'base64url');
  if (raw.length !== 32 || raw.toString('base64url') !== base64url) return null;
  try {
    return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
  } catch {
    return null;
  }
}

/**
 * EVIDENCE_SIGNING_KEY's value: the base64 of an Ed25519 private key's PKCS#8 DER, one line, as
 * scripts/evidence-keygen.ts writes it. Null for anything else (the server then signs nothing).
 */
export function privateKeyFrom(value: string): KeyObject | null {
  const text = value.trim();
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text)) return null;
  try {
    const key = createPrivateKey({ key: Buffer.from(text, 'base64'), format: 'der', type: 'pkcs8' });
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

/** One published key. `until` null: still in use. A statement verifies under a key only if its time is in [from, until). */
export const PublishedKey = z
  .object({
    kid: z.string().regex(/^ev-ed25519-[0-9a-f]{16}$/),
    alg: z.literal(ALG),
    publicKey: z.string().regex(/^[A-Za-z0-9_-]{43}$/, 'the raw 32-byte public key, base64url'),
    from: z.iso.datetime({ offset: false }),
    until: z.iso.datetime({ offset: false }).nullable(),
  })
  .strict();
export type PublishedKey = z.infer<typeof PublishedKey>;
export const KeysFile = z.object({ keys: z.array(PublishedKey).max(50) }).strict();
export type KeysFile = z.infer<typeof KeysFile>;

/** Whether a time falls in a key's window, [from, until). */
export const inWindow = (k: Pick<PublishedKey, 'from' | 'until'>, at: string) => {
  const t = Date.parse(at);
  return Number.isFinite(t) && t >= Date.parse(k.from) && (k.until === null || t < Date.parse(k.until));
};

export interface Signature {
  alg: typeof ALG;
  kid: string;
  /** base64url of the 64-byte Ed25519 signature over signedBytes(statement). */
  value: string;
}

/** The server's key, ready to sign: the private key, its key id and its published entry. */
export interface Signer {
  kid: string;
  privateKey: KeyObject;
}

export function signStatement(statement: unknown, signer: Signer): Signature {
  return { alg: ALG, kid: signer.kid, value: sign(null, signedBytes(statement), signer.privateKey).toString('base64url') };
}

/**
 * The server's signer from the key and the published keys: only a key whose id is published, with
 * the same public key and a window that covers `now`, signs. Anything else is unsigned with the
 * reason, so the server never writes evidence that `teardown verify` would reject.
 */
export const NO_SIGNING_KEY = 'No evidence signing key is configured on Teardown’s server.';

export function signerFor(privateKey: KeyObject | null, keys: KeysFile, now: Date): { signer: Signer } | { unsigned: string } {
  if (!privateKey) return { unsigned: NO_SIGNING_KEY };
  const publicKey = createPublicKey(privateKey);
  const kid = keyIdOf(publicKey);
  const entry = keys.keys.find((k) => k.kid === kid);
  if (!entry || entry.publicKey !== rawPublicKey(publicKey).toString('base64url')) return { unsigned: `The server’s signing key (${kid}) isn’t published at ${KEYS_PATH}.` };
  if (!inWindow(entry, now.toISOString())) return { unsigned: `The server’s signing key (${kid}) is outside its published validity window.` };
  return { signer: { kid, privateKey } };
}

/** What verifying a signature found: ok, or every reason it failed. */
export interface SignatureCheck {
  ok: boolean;
  failures: string[];
}

/** Checks a statement's signature against the published keys: the key id, its window, the algorithm and the signature itself. */
export function verifySignature(statement: unknown, signature: unknown, keys: KeysFile): SignatureCheck {
  const failures: string[] = [];
  const sig = z.object({ alg: z.string(), kid: z.string(), value: z.string() }).strict().safeParse(signature);
  if (!sig.success) return { ok: false, failures: ['signature: missing or malformed.'] };
  const s = statement as { signing?: { kid?: unknown }; decidedAt?: unknown } | null;
  if (sig.data.alg !== ALG) failures.push(`signature: the algorithm is ${sig.data.alg}, not ${ALG}.`);
  const entry = keys.keys.find((k) => k.kid === sig.data.kid);
  if (!entry) return { ok: false, failures: [...failures, `key: ${sig.data.kid} isn’t a published key id.`] };
  if (s?.signing?.kid !== sig.data.kid) failures.push(`key: the statement names ${String(s?.signing?.kid)}, the signature ${sig.data.kid}.`);
  if (typeof s?.decidedAt !== 'string' || !inWindow(entry, s.decidedAt)) failures.push(`key: ${entry.kid} is valid from ${entry.from}${entry.until ? ` until ${entry.until}` : ''}, and the statement is dated ${String(s?.decidedAt)}.`);
  const publicKey = publicKeyFrom(entry.publicKey);
  const value = Buffer.from(sig.data.value, 'base64url');
  if (!publicKey) failures.push(`key: ${entry.kid}’s published public key isn’t an Ed25519 key.`);
  else if (value.length !== 64 || !verify(null, signedBytes(statement), publicKey, value)) failures.push('signature: doesn’t match the statement. The evidence was changed after Teardown signed it, or wasn’t signed by this key.');
  return { ok: failures.length === 0, failures };
}
