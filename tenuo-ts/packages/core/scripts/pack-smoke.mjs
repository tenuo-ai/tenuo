import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const coreDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const packDir = mkdtempSync(join(tmpdir(), "tenuo-core-pack-"));
const installDir = mkdtempSync(join(tmpdir(), "tenuo-core-smoke-"));

try {
  const packed = execFileSync("pnpm", ["pack", "--pack-destination", packDir], {
    cwd: coreDir,
    encoding: "utf8",
  })
    .trim()
    .split("\n")
    .at(-1);
  if (packed === undefined || packed.length === 0) {
    throw new Error("pnpm pack did not print a tarball path");
  }
  const tarball = packed.startsWith("/") ? packed : join(packDir, packed);

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
