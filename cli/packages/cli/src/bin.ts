import { spawn } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { main, type CliIo } from '../../../src/lib/gate/cli';

/** The CLI on a real machine: the working directory's files, the network and the process. */
const cwd = process.cwd();
const inside = (p: string) => {
  const full = path.resolve(cwd, p);
  if (full !== cwd && !full.startsWith(cwd + path.sep)) throw new Error(`${p} is outside the working directory.`);
  return full;
};
const io: CliIo = {
  cwd,
  env: process.env,
  list: (dir) => {
    const full = inside(dir);
    if (!existsSync(full)) return [];
    return readdirSync(full).filter((n) => statSync(path.join(full, n)).isFile());
  },
  read: (file) => {
    const full = inside(file);
    return existsSync(full) && statSync(full).isFile() ? readFileSync(full, 'utf8') : null;
  },
  write: (file, text) => writeFileSync(inside(file), text),
  fetch: (input, init) => fetch(input, init),
  out: (line) => console.log(line),
  err: (line) => console.error(line),
  now: () => new Date(),
  exec: (cmd, args) =>
    new Promise((resolve) => {
      const child = spawn(cmd, args, { cwd, stdio: 'inherit', shell: false });
      child.on('close', (code) => resolve(code ?? 1));
      child.on('error', () => resolve(127));
    }),
};

main(process.argv.slice(2), io).then(
  (code) => process.exit(code),
  (e: unknown) => {
    console.error(`teardown: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(2);
  },
);
