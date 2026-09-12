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
  assertPackageContents(installDir, "@tenuo/mcp", [
    /^package\.json$/,
    /^LICENSE$/,
    /^README\.md$/,
    /^dist\/[^/]+\.js$/,
    /^dist\/[^/]+\.js\.map$/,
    /^dist\/[^/]+\.d\.ts$/,
  ]);
  run("npm", ["install", "--save-dev", "typescript@~5.8.2", "@types/node@^20.0.0"], {
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

