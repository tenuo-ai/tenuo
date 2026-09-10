import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  copyFileSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const exampleDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const coreDir = resolve(exampleDir, "../../packages/core");
const repositoryRoot = resolve(exampleDir, "../../..");
const packDir = mkdtempSync(join(tmpdir(), "tenuo-core-next-pack-"));
const installDir = mkdtempSync(join(tmpdir(), "tenuo-next-example-"));
let server;

try {
  copyFileSync(join(repositoryRoot, "LICENSE"), join(coreDir, "LICENSE"));
  const tarball = packPackage(coreDir, packDir);

  cpSync(exampleDir, installDir, {
    recursive: true,
    filter: (source) =>
      !["node_modules", ".next"].includes(
        relative(exampleDir, source).split(/[\\/]/)[0],
      ),
  });

  const packageJsonPath = join(installDir, "package.json");
  const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"));
  packageJson.dependencies["@tenuo/core"] =
    `file:${tarball.replaceAll("\\", "/")}`;
  writeFileSync(packageJsonPath, `${JSON.stringify(packageJson, null, 2)}\n`);

  runNpm(["install", "--no-audit", "--no-fund"], installDir);
  assertPackedInstall(installDir);
  runNpm(["run", "typecheck"], installDir);
  runNpm(["run", "build"], installDir);

  const port = await availablePort();
  server = spawn(
    process.execPath,
    [
      join(installDir, "node_modules", "next", "dist", "bin", "next"),
      "start",
      "--hostname",
      "127.0.0.1",
      "--port",
      String(port),
    ],
    {
      cwd: installDir,
      env: {
        ...process.env,
        NEXT_TELEMETRY_DISABLED: "1",
        NODE_ENV: "production",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  let output = "";
  server.stdout.on("data", (chunk) => {
    output += chunk;
    process.stdout.write(chunk);
  });
  server.stderr.on("data", (chunk) => {
    output += chunk;
    process.stderr.write(chunk);
  });

  const origin = `http://127.0.0.1:${port}`;
  await waitForServer(
    `${origin}/api/read?path=${encodeURIComponent("/data/report.txt")}`,
    server,
    () => output,
  );

  const allowed = await requestJson(
    `${origin}/api/read?path=${encodeURIComponent("/data/report.txt")}`,
  );
  assert.equal(allowed.status, 200);
  assert.deepEqual(allowed.body, {
    allowed: true,
    path: "/data/report.txt",
    result: "contents of /data/report.txt",
  });

  const denied = await requestJson(
    `${origin}/api/read?path=${encodeURIComponent("/etc/passwd")}`,
  );
  assert.equal(denied.status, 403);
  assert.deepEqual(denied.body, {
    allowed: false,
    code: "TENUO_CONSTRAINT_VIOLATION",
    path: "/etc/passwd",
  });

  console.log(
    "Verified packed @tenuo/core with allowed (200) and denied (403) production responses.",
  );
} finally {
  if (server) await stopServer(server);
  rmSync(packDir, {
    recursive: true,
    force: true,
    maxRetries: 5,
    retryDelay: 200,
  });
  rmSync(installDir, {
    recursive: true,
    force: true,
    maxRetries: 5,
    retryDelay: 200,
  });
}

function npmInvocation(args) {
  if (process.platform === "win32") {
    const npmCli = join(
      dirname(process.execPath),
      "node_modules",
      "npm",
      "bin",
      "npm-cli.js",
    );
    if (existsSync(npmCli))
      return { command: process.execPath, args: [npmCli, ...args] };
  }
  return { command: "npm", args };
}

function runNpm(args, cwd) {
  const invocation = npmInvocation(args);
  run(invocation.command, invocation.args, cwd);
}

function run(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    env: { ...process.env, NEXT_TELEMETRY_DISABLED: "1" },
    stdio: "inherit",
  });
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} exited with status ${result.status ?? "unknown"}`,
    );
  }
}

function packPackage(cwd, destination) {
  const invocation = npmInvocation(["pack", "--pack-destination", destination]);
  const result = spawnSync(invocation.command, invocation.args, {
    cwd,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    if (result.stderr) process.stderr.write(result.stderr);
    if (result.error) throw result.error;
    throw new Error(
      `npm pack exited with status ${result.status ?? "unknown"}`,
    );
  }
  process.stdout.write(result.stdout);
  const packed = result.stdout.trim().split(/\r?\n/).at(-1);
  if (packed === undefined || packed.length === 0) {
    throw new Error("npm pack did not print a tarball path");
  }
  return isAbsolute(packed) ? packed : join(destination, packed);
}

function assertPackedInstall(root) {
  const packageDir = join(root, "node_modules", "@tenuo", "core");
  assert.equal(
    lstatSync(packageDir).isSymbolicLink(),
    false,
    "@tenuo/core must not be a workspace symlink",
  );
  assert.equal(
    realpathSync(packageDir).startsWith(realpathSync(root)),
    true,
    "@tenuo/core must be installed inside the isolated example",
  );
  assert.equal(
    existsSync(join(packageDir, "dist", "generated", "tenuo_wasm_bg.wasm")),
    true,
    "the packed @tenuo/core must contain its generated WASM asset",
  );
}

async function availablePort() {
  const listener = createServer();
  await new Promise((resolvePromise, reject) => {
    listener.once("error", reject);
    listener.listen(0, "127.0.0.1", resolvePromise);
  });
  const address = listener.address();
  assert.notEqual(address, null);
  assert.equal(typeof address, "object");
  const port = address.port;
  await new Promise((resolvePromise, reject) =>
    listener.close((error) => (error ? reject(error) : resolvePromise())),
  );
  return port;
}

async function waitForServer(url, child, getOutput) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`Next.js exited before becoming ready.\n${getOutput()}`);
    }
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // The production server is still starting.
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 200));
  }
  throw new Error(`Timed out waiting for Next.js.\n${getOutput()}`);
}

async function stopServer(child) {
  if (child.exitCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolvePromise) => child.once("exit", resolvePromise)),
    new Promise((resolvePromise) => setTimeout(resolvePromise, 5_000)),
  ]);
}

async function requestJson(url) {
  const response = await fetch(url);
  return { status: response.status, body: await response.json() };
}
