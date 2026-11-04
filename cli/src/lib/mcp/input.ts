import { z } from 'zod';

/**
 * What an MCP tool call may send (docs/research/2026-10-26-mcp-spike.md, section 2): dependency
 * files by an allowlist of names, or a public repository URL. Never application code: any other
 * file is refused by name before anything is read.
 */

/** The request body's cap, under Vercel's 4.5MB, and every file together. */
export const MCP_MAX_BYTES = 4 * 1024 * 1024;
/** Files per call. */
export const MCP_MAX_FILES = 24;

/** Lockfiles and manifests, by exact name. */
const LOCK_AND_MANIFEST = new Set([
  'package-lock.json',
  'package.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'composer.lock',
  'composer.json',
  'poetry.lock',
  'uv.lock',
  'pyproject.toml',
  'Pipfile.lock',
  'Pipfile',
  'Gemfile.lock',
  'Cargo.lock',
  'Cargo.toml',
  'go.mod',
  'gradle.lockfile',
]);
/** Version files, read only for the runtime's version. */
const VERSION_FILES = new Set(['.nvmrc', '.node-version', '.php-version', '.python-version', '.tool-versions', 'runtime.txt', 'Dockerfile']);
/** SBOMs and pinned requirements files, by pattern. */
const SBOM = /^(?:s?bom\.json|[A-Za-z0-9._-]{1,100}\.(?:cdx|spdx)\.json)$/i;
const REQUIREMENTS = /^requirements(?:[-_.][A-Za-z0-9_-]{1,40})?\.txt$/;
/** The only paths with a directory: pinned requirements under requirements/, and workflows. */
const REQUIREMENTS_DIR = /^requirements\/[A-Za-z0-9_-]{1,40}\.txt$/;
const WORKFLOW = /^\.github\/workflows\/[A-Za-z0-9._-]{1,100}\.ya?ml$/;

/** Whether a file name is one Teardown reads. */
export function allowedFileName(name: string): boolean {
  if (name.includes('..') || name.startsWith('/') || name.includes('\\')) return false;
  if (WORKFLOW.test(name) || REQUIREMENTS_DIR.test(name)) return true;
  if (name.includes('/')) return false;
  return LOCK_AND_MANIFEST.has(name) || VERSION_FILES.has(name) || SBOM.test(name) || REQUIREMENTS.test(name);
}

export const McpFile = z.object({
  name: z.string().min(1).max(160),
  text: z.string().max(MCP_MAX_BYTES),
});
export type McpFile = z.infer<typeof McpFile>;

const RepoUrl = z
  .string()
  .max(300)
  .regex(/^https:\/\/(?:github\.com|gitlab\.com)\/[A-Za-z0-9._-]{1,100}\/[A-Za-z0-9._-]{1,100}(?:\/)?$/, 'a public github.com or gitlab.com repository URL');

/** Where the app comes from: files, or a repository. */
export const McpSource = z
  .object({
    files: z.array(McpFile).min(1).max(MCP_MAX_FILES).optional(),
    repo: RepoUrl.optional(),
  })
  .strict()
  .refine((s) => (s.files ? 1 : 0) + (s.repo ? 1 : 0) === 1, 'send either files or repo');
export type McpSource = z.infer<typeof McpSource>;

export class McpInputError extends Error {}

/** The files, checked: every name on the allowlist, within the size caps. */
export function checkFiles(files: McpFile[]): McpFile[] {
  const refused = files.filter((f) => !allowedFileName(f.name)).map((f) => f.name);
  if (refused.length) {
    throw new McpInputError(
      // Never “and 1 more”: six are all named (the rule in src/lib/cut.ts, inlined: this file ships in the CLI).
      `Teardown reads lockfiles, manifests, SBOMs and version files only. Not sent: ${refused.slice(0, refused.length === 6 ? 6 : 5).join(', ')}${refused.length > 6 ? ` and ${refused.length - 5} more` : ''}.`,
    );
  }
  const total = files.reduce((n, f) => n + Buffer.byteLength(f.text, 'utf8'), 0);
  if (total > MCP_MAX_BYTES) throw new McpInputError('The files are larger than 4MB together, the most Teardown reads in one call.');
  const names = new Set<string>();
  for (const f of files) {
    if (names.has(f.name)) throw new McpInputError(`${f.name} was sent twice.`);
    names.add(f.name);
  }
  return files;
}
