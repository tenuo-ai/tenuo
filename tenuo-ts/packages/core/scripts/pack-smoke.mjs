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
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import {
  committedWasmSha256,
  resolveSourceCommit,
  sha256,
  sourceIsClean,
  WASM_SOURCE_PATH,
} from "./build-provenance.mjs";

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
    "dist/build-info.json",
    "dist/generated/tenuo_wasm_bg.wasm",
    "dist/generated/tenuo_wasm.js",
    "LICENSE",
    "README.md",
  ]);
  assertPackageContents(installDir, "@tenuo/core", [
    /^package\.json$/,
    /^LICENSE$/,
    /^README\.md$/,
    /^dist\/build-info\.json$/,
    /^dist\/[^/]+\.js$/,
    /^dist\/[^/]+\.js\.map$/,
    /^dist\/[^/]+\.d\.ts$/,
    /^dist\/generated\/(package\.json|tenuo_wasm\.js|tenuo_wasm\.d\.ts)$/,
    /^dist\/generated\/(tenuo_wasm_bg\.wasm|tenuo_wasm_bg\.wasm\.d\.ts)$/,
  ]);
  assertBuildInfo(installDir, "@tenuo/core");
  // The major selector is equivalent to ^20.0.0 without cmd.exe's caret escape.
  run("npm", ["install", "--save-dev", "typescript@~5.8.2", "@types/node@20"], {
    cwd: installDir,
    stdio: "inherit",
  });
  writeFileSync(join(installDir, "consumer.ts"), `
    import { createTenuo, under, type ProtectedTool, type Session } from "@tenuo/core";
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const inner = { execute: async ({ path }: { path: string }) => path };
    const tool = tenuo.tool(inner, {
      capability: "read_file",
      allow: { path: under("/data") },
    });
    const typedTool: ProtectedTool<typeof inner> = tool;
    const result: string = await tool.execute({ path: "/data/q3.pdf" });
    const session: Session = tenuo.session({ tools: [tool] });
    await tenuo.withSession(session, () => tool.execute({ path: "/data/q3.pdf" }));
  `);
  typecheckConsumer(installDir);

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
    for (const [index, source] of sources.entries()) {
      const sourcePath = resolve(coreDir, dirname(map), source);
      if (!existsSync(sourcePath)) {
        throw new Error(`${map} references missing repository source ${source}`);
      }
      if (readFileSync(sourcePath, "utf8") !== sourcesContent[index]) {
        throw new Error(
          `${map} embeds source for ${source} that differs from the working tree; rebuild, or commit/stash local edits`,
        );
      }
    }
  }
}

function assertBuildInfo(root, packageName) {
  const packageDir = join(root, "node_modules", ...packageName.split("/"));
  const info = JSON.parse(readFileSync(join(packageDir, "dist", "build-info.json"), "utf8"));
  const manifest = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8"));
  const commit = resolveSourceCommit(coreDir);
  const wasm = readFileSync(join(packageDir, "dist", "generated", "tenuo_wasm_bg.wasm"));
  if (info.package !== packageName || info.version !== manifest.version || info.sourceCommit !== commit) {
    throw new Error("build-info.json does not identify this package version and source commit");
  }
  const digest = sha256(wasm);
  if (info.wasmSha256 !== digest) {
    throw new Error("build-info.json does not identify the packed WASM artifact");
  }
  // The two qualifiers are recomputed rather than read back, so a stale or
  // hand-edited build-info.json cannot overstate provenance. They are not
  // required to be true: `pnpm test` recompiles the WASM, and wasm-pack is not
  // byte-reproducible, so a legitimate CI build packs a binary that differs
  // from the committed one and says so.
  if (info.wasmMatchesCommit !== (digest === committedWasmSha256(coreDir, commit))) {
    throw new Error(
      `build-info.json misreports whether the packed WASM is ${WASM_SOURCE_PATH} as committed at ${commit}`,
    );
  }
  if (info.sourceClean !== sourceIsClean(coreDir)) {
    throw new Error("build-info.json misreports whether the source tree was clean");
  }
}

function typecheckConsumer(cwd) {
  writeFileSync(
    join(cwd, "tsconfig.json"),
    JSON.stringify({
      compilerOptions: {
        target: "ES2022",
        module: "NodeNext",
        moduleResolution: "NodeNext",
        strict: true,
        noEmit: true,
        skipLibCheck: false,
      },
      files: ["consumer.ts"],
    }),
  );
  run(process.execPath, [join(cwd, "node_modules", "typescript", "bin", "tsc"), "--noEmit"], {
    cwd,
    stdio: "inherit",
  });
}
