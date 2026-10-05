import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const exampleDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const coreDir = resolve(exampleDir, "../../packages/core");
const packDir = mkdtempSync(join(tmpdir(), "tenuo-core-vercel-pack-"));
const installDir = mkdtempSync(join(tmpdir(), "tenuo-vercel-example-"));

try {
  const tarball = packPackage(coreDir, packDir);

  cpSync(exampleDir, installDir, {
    recursive: true,
    filter: (source) =>
      !["node_modules", "scripts"].includes(
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
  runNpm(["test"], installDir);
  runNpm(["run", "demo"], installDir);

  console.log(
    "Verified packed @tenuo/core with the Vercel AI SDK example: typecheck, tests, and demo all pass.",
  );
} finally {
  rmSync(packDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  rmSync(installDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
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
    env: process.env,
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
    throw new Error(`npm pack exited with status ${result.status ?? "unknown"}`);
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
    existsSync(packageDir),
    true,
    "npm install did not produce node_modules/@tenuo/core",
  );
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
