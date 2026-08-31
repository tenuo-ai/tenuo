import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const coreDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const packDir = mkdtempSync(join(tmpdir(), "tenuo-core-pack-"));
const installDir = mkdtempSync(join(tmpdir(), "tenuo-core-smoke-"));

try {
  const tarball = packPackage(coreDir, packDir);
  assertPacked(tarball, [
    "package/dist/index.js",
    "package/dist/generated/tenuo_wasm_bg.wasm",
    "package/dist/generated/tenuo_wasm.js",
    "package/LICENSE",
    "package/README.md",
  ]);

  writeFileSync(join(installDir, "package.json"), JSON.stringify({ private: true, type: "module" }));
  execFileSync("npm", ["install", "--omit=dev", tarball], {
    cwd: installDir,
    stdio: "inherit",
  });
  execFileSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `
        import { createTenuo, under } from "@tenuo/core";
        const tenuo = createTenuo({ root: createTenuo.devRoot() });
        const readFile = tenuo.tool(
          { execute: async ({ path }) => path },
          { capability: "read_file", allow: { path: under("/data") } },
        );
        const session = tenuo.session({ tools: [readFile] });
        const got = await tenuo.withSession(session, () =>
          readFile.execute({ path: "/data/q3.pdf" }),
        );
        if (got !== "/data/q3.pdf") {
          throw new Error("unexpected execute result: " + got);
        }
        await tenuo.withSession(session, () => readFile.execute({ path: "/etc/passwd" })).then(
          () => { throw new Error("deny must not execute"); },
          (error) => {
            if (error?.code !== "TENUO_CONSTRAINT_VIOLATION") {
              throw new Error("unexpected deny: " + error);
            }
          },
        );
        const call = tenuo.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
        const verified = tenuo.mcp.verify(call.name, call.arguments, call._meta, {
          allow: { path: under("/data") },
        });
        if (verified.path !== "/data/q3.pdf") {
          throw new Error("unexpected verify result: " + JSON.stringify(verified));
        }
        console.log("pack smoke ok");
      `,
    ],
    {
      cwd: installDir,
      stdio: "inherit",
      env: { ...process.env, NODE_ENV: "test" },
    },
  );
} finally {
  rmSync(packDir, { recursive: true, force: true });
  rmSync(installDir, { recursive: true, force: true });
}

function packPackage(cwd, destination) {
  const packed = execFileSync("pnpm", ["pack", "--pack-destination", destination], {
    cwd,
    encoding: "utf8",
  })
    .trim()
    .split("\n")
    .at(-1);
  if (packed === undefined || packed.length === 0) {
    throw new Error("pnpm pack did not print a tarball path");
  }
  return packed.startsWith("/") ? packed : join(destination, packed);
}

function assertPacked(tarball, required) {
  const listing = execFileSync("tar", ["-tzf", tarball], { encoding: "utf8" });
  for (const path of required) {
    if (!listing.split("\n").includes(path)) {
      throw new Error(`packed tarball is missing ${path}`);
    }
  }
}
