import { execFileSync } from "node:child_process";
import { copyFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
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
  assertPacked(mcpTarball, [
    "package/dist/index.js",
    "package/dist/index.d.ts",
    "package/dist/index.d.ts.map",
    "package/LICENSE",
    "package/README.md",
  ]);

  writeFileSync(join(installDir, "package.json"), JSON.stringify({ private: true, type: "module" }));
  execFileSync("npm", ["install", "--omit=dev", coreTarball, mcpTarball], {
    cwd: installDir,
    stdio: "inherit",
  });
  execFileSync("npm", ["install", "--save-dev", "typescript@~5.8.2", "@types/node@^20.0.0"], {
    cwd: installDir,
    stdio: "inherit",
  });
  writeFileSync(join(installDir, "consumer.ts"), `
    import { McpServer } from "@modelcontextprotocol/server";
    import { createTenuo, under } from "@tenuo/core";
    import { guardHandler, guardTools, type GuardHandlerCallback } from "@tenuo/mcp";
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const callback: GuardHandlerCallback<{ path: string }> = async ({ path }) => ({
      content: [{ type: "text", text: path }],
    });
    const guarded = guardHandler(tenuo, "read_file", { allow: { path: under("/data") } }, callback);
    await guarded({ path: "/data/q3.pdf" });
    const server = new McpServer({ name: "consumer", version: "1.0.0" });
    guardTools(tenuo, server).register("health", {}, async () => ({
      content: [{ type: "text", text: "ok" }],
    }));
  `);
  typecheckConsumer(installDir);

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
  execFileSync(join(cwd, "node_modules", ".bin", "tsc"), ["--noEmit"], {
    cwd,
    stdio: "inherit",
  });
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
