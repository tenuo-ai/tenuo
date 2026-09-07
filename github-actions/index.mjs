import { spawnSync } from 'node:child_process';
import { appendFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { actionRoot, installRuntime } from './install-runtime.mjs';

const input = (name) => process.env[`INPUT_${name.toUpperCase()}`] || '';
const actionPath = actionRoot();
const runDir = join(process.env.RUNNER_TEMP || '/tmp', 'tenuo', process.env.GITHUB_RUN_ID || 'local');
mkdirSync(runDir, { recursive: true });

const socket = join(runDir, 'holder.sock');
const pid = join(runDir, 'holder.pid');
const mcpConfig = join(runDir, 'mcp-config.json');
const python = process.env.TENUO_PYTHON || 'python';

installRuntime(python, actionPath);

const env = {
  ...process.env,
  PYTHONPATH: actionPath + (process.env.PYTHONPATH ? `:${process.env.PYTHONPATH}` : ''),
  TENUO_GATEWAY_URL: input('gateway_url'),
  TENUO_EXCHANGE_URL: input('exchange_url'),
  TENUO_EXCHANGE_AUDIENCE: input('audience'),
  TENUO_TRUSTED_ROOTS: input('trusted_roots'),
};
const started = spawnSync(
  python,
  [
    '-m', 'tenuo_gha', 'action',
    '--gateway-url', input('gateway_url'),
    '--exchange-url', input('exchange_url') || input('gateway_url'),
    '--audience', input('audience'),
    '--ttl', input('ttl') || '900',
    '--mcp-config', mcpConfig,
    '--socket', socket,
    '--pid', pid,
    '--trusted-roots', input('trusted_roots'),
  ],
  { stdio: 'inherit', env },
);
if (started.status !== 0) process.exit(started.status ?? 1);

const state = process.env.GITHUB_STATE;
if (state) {
  appendFileSync(state, `socket=${socket}\n`);
  appendFileSync(state, `pid=${pid}\n`);
  appendFileSync(state, `mcp_config=${mcpConfig}\n`);
  appendFileSync(state, `run_dir=${runDir}\n`);
  appendFileSync(state, `action_path=${actionPath}\n`);
}
