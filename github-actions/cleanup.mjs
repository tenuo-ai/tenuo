import { spawnSync } from 'node:child_process';
import { rmSync } from 'node:fs';

const socket = process.env.STATE_SOCKET || '';
const pid = process.env.STATE_PID || '';
const mcpConfig = process.env.STATE_MCP_CONFIG || '';
const runDir = process.env.STATE_RUN_DIR || '';
const actionPath = process.env.STATE_ACTION_PATH || process.env.GITHUB_ACTION_PATH || '';
const python = process.env.TENUO_PYTHON || 'python';

const env = {
  ...process.env,
  PYTHONPATH: actionPath + (process.env.PYTHONPATH ? `:${process.env.PYTHONPATH}` : ''),
};
const args = ['-m', 'tenuo_gha', 'stop'];
if (socket) args.push('--socket', socket);
if (pid) args.push('--pid', pid);
if (mcpConfig) args.push('--mcp-config', mcpConfig);
spawnSync(python, args, { stdio: 'inherit', env });
if (runDir) {
  try {
    rmSync(runDir, { recursive: true, force: true });
  } catch (error) {
    if (error.code !== 'ENOENT') console.warn(`Could not remove Tenuo run directory: ${error.message}`);
  }
}
