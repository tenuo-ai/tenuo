import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export function findTenuoWheel(actionPath) {
  if (process.env.TENUO_WHEEL) {
    return process.env.TENUO_WHEEL;
  }
  const vendor = join(actionPath, 'vendor');
  if (!existsSync(vendor)) {
    return '';
  }
  const wheels = readdirSync(vendor)
    .filter((name) => /^tenuo-.*\.whl$/.test(name))
    .sort();
  return wheels.length ? join(vendor, wheels[wheels.length - 1]) : '';
}

export function installRuntime(python, actionPath) {
  const wheel = findTenuoWheel(actionPath);
  if (!wheel) {
    console.error(
      'Tenuo runtime wheel is missing. Package the compatible tenuo wheel into vendor/ or set TENUO_WHEEL.',
    );
    process.exit(1);
  }

  const lock = spawnSync(
    python,
    [
      '-m', 'pip', 'install', '--disable-pip-version-check', '--quiet', '--require-hashes',
      '-r', join(actionPath, 'requirements.lock'),
    ],
    { stdio: 'inherit', env: process.env },
  );
  if (lock.status !== 0) process.exit(lock.status ?? 1);
  const runtime = spawnSync(
    python,
    ['-m', 'pip', 'install', '--disable-pip-version-check', '--quiet', wheel],
    { stdio: 'inherit', env: process.env },
  );
  if (runtime.status !== 0) process.exit(runtime.status ?? 1);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const actionPath = process.env.GITHUB_ACTION_PATH || process.cwd();
  installRuntime(process.env.TENUO_PYTHON || 'python', actionPath);
}
