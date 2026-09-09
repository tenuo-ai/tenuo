import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const coreDir = join(dirname(fileURLToPath(import.meta.url)), "..");
copyFileSync(join(coreDir, "..", "..", "..", "LICENSE"), join(coreDir, "LICENSE"));
const packDir = mkdtempSync(join(tmpdir(), "tenuo-core-pack-"));
const installDir = mkdtempSync(join(tmpdir(), "tenuo-core-smoke-"));

try {
  const tarball = packPackage(coreDir, packDir);
  writeFileSync(join(installDir, "package.json"), JSON.stringify({ private: true, type: "module" }));
  run("npm", ["install", "--omit=dev", tarball], { cwd: installDir, stdio: "inherit" });
  assertInstalled(installDir, "@tenuo/core", [
    "dist/index.js",
    "dist/generated/tenuo_wasm_bg.wasm",
    "dist/generated/tenuo_wasm.js",
    "LICENSE",
    "README.md",
  ]);
  assertPackageContents(installDir, "@tenuo/core", [
    /^package\.json$/,
    /^LICENSE$/,
    /^README\.md$/,
    /^dist\/[^/]+\.js$/,
    /^dist\/[^/]+\.js\.map$/,
    /^dist\/[^/]+\.d\.ts$/,
    /^dist\/generated\/(package\.json|tenuo_wasm\.js|tenuo_wasm\.d\.ts)$/,
    /^dist\/generated\/(tenuo_wasm_bg\.wasm|tenuo_wasm_bg\.wasm\.d\.ts)$/,
  ]);
  copyFileSync(join(coreDir, "scripts", "pack-smoke-consumer.mjs"), join(installDir, "smoke.mjs"));
  execFileSync(process.execPath, [join(installDir, "smoke.mjs")], {
    cwd: installDir,
    stdio: "inherit",
    env: { ...process.env, NODE_ENV: "test" },
  });
} finally {
  rmSync(packDir, { recursive: true, force: true });
  rmSync(installDir, { recursive: true, force: true });
}

function run(command, args, options) {
  return execFileSync(command, args, {
    ...options,
    shell: process.platform === "win32",
  });
}

function packPackage(cwd, destination) {
  const packed = run("pnpm", ["pack", "--pack-destination", destination], {
    cwd,
    encoding: "utf8",
  })
    .trim()
    .split(/\r?\n/)
    .at(-1);
  if (packed === undefined || packed.length === 0) {
    throw new Error("pnpm pack did not print a tarball path");
  }
  return isAbsolute(packed) ? packed : join(destination, packed);
}

function assertInstalled(root, packageName, required) {
  const packageDir = join(root, "node_modules", ...packageName.split("/"));
  for (const path of required) {
    if (!existsSync(join(packageDir, path))) {
      throw new Error(`installed ${packageName} is missing ${path}`);
    }
  }
}

function listFiles(dir) {
  const files = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listFiles(path));
    } else {
      files.push(path);
    }
  }
  return files;
}

// The tarball ships dist only, so a map's ../src/*.ts path never resolves for
// consumers; JavaScript maps must carry sourcesContent instead. Only top-level
// dist/*.js is checked: dist/generated is wasm-bindgen output with no maps.
function assertPackageContents(root, packageName, allowed) {
  const packageDir = join(root, "node_modules", ...packageName.split("/"));
  const files = listFiles(packageDir).map((file) => relative(packageDir, file).split(sep).join("/"));
  const unexpected = files.filter((file) => !allowed.some((pattern) => pattern.test(file)));
  if (unexpected.length > 0) {
    throw new Error(`installed ${packageName} contains unexpected files: ${unexpected.join(", ")}`);
  }
  for (const emitted of files.filter((file) => /^dist\/[^/]+\.js$/.test(file))) {
    const map = `${emitted}.map`;
    if (!files.includes(map)) {
      throw new Error(`installed ${packageName} is missing ${map}`);
    }
    const { sources, sourcesContent } = JSON.parse(readFileSync(join(packageDir, map), "utf8"));
    if (!Array.isArray(sourcesContent) || sourcesContent.length !== sources.length) {
      throw new Error(`${map} must embed sourcesContent for every source`);
    }
    if (sourcesContent.some((content) => typeof content !== "string" || content.length === 0)) {
      throw new Error(`${map} has an empty sourcesContent entry`);
    }
  }
}
