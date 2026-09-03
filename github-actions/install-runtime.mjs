import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const UBUNTU_WHEEL = /manylinux|linux_/;

export function runnerIsUbuntu() {
  return process.platform === 'linux';
}

export function findTenuoWheel(actionPath) {
  if (process.env.TENUO_WHEEL) {
    return process.env.TENUO_WHEEL;
  }
  const vendor = join(actionPath, 'vendor');
  if (!existsSync(vendor)) {
    return '';
  }
  const wheels = readdirSync(vendor).filter((name) => /^tenuo-.*\.whl$/.test(name)).sort();
  if (!wheels.length) {
    return '';
  }
  if (!runnerIsUbuntu()) {
    console.error(
      'This action currently supports Ubuntu runners. Package a manylinux tenuo wheel into vendor/ and run on ubuntu-latest.',
    );
    process.exit(1);
  }
  const matched = wheels.filter((name) => UBUNTU_WHEEL.test(name));
  return matched.length ? join(vendor, matched[matched.length - 1]) : '';
}

export function installRuntime(python, actionPath) {
  const wheel = findTenuoWheel(actionPath);
  if (!wheel) {
    console.error(
      'Tenuo runtime wheel is missing. Package the compatible Ubuntu tenuo wheel into vendor/ with package_runtime.py.',
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
