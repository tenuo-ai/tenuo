import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

const mcpDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const coreDir = join(mcpDir, "..", "core");
const repoLicense = join(mcpDir, "..", "..", "..", "LICENSE");
copyFileSync(repoLicense, join(coreDir, "LICENSE"));
copyFileSync(repoLicense, join(mcpDir, "LICENSE"));
const packDir = mkdtempSync(join(tmpdir(), "tenuo-mcp-pack-"));
const installDir = mkdtempSync(join(tmpdir(), "tenuo-mcp-smoke-"));

try {
  const coreTarball = packPackage(coreDir, packDir);
  const mcpTarball = packPackage(mcpDir, packDir);
  writeFileSync(join(installDir, "package.json"), JSON.stringify({ private: true, type: "module" }));
  run("npm", ["install", "--omit=dev", coreTarball, mcpTarball], {
    cwd: installDir,
    stdio: "inherit",
  });
  assertInstalled(installDir, "@tenuo/mcp", ["dist/index.js", "LICENSE", "README.md"]);
  execFileSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `
        import { createTenuo, under } from "@tenuo/core";
        import { guardHandler } from "@tenuo/mcp";
        const tenuo = createTenuo({ root: createTenuo.devRoot() });
        const session = tenuo.session({
          allow: { read_file: { path: under("/data") } },
        });
        const call = tenuo.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
        let executed = false;
        const handler = guardHandler(
          tenuo,
          "read_file",
          { allow: { path: under("/data") } },
          async ({ path }) => {
            executed = true;
            return { content: [{ type: "text", text: path }] };
          },
        );
        const allowed = await handler(call.arguments, { mcpReq: { _meta: call._meta } });
        if (allowed.isError === true || allowed.content?.[0]?.text !== "/data/q3.pdf" || !executed) {
          throw new Error("expected allow: " + JSON.stringify(allowed));
        }
        executed = false;
        const denied = await handler({ path: "/data/q3.pdf" }, {});
        if (denied.isError !== true || executed) {
          throw new Error("expected deny without execute: " + JSON.stringify(denied));
        }
        console.log("mcp pack smoke ok");
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
