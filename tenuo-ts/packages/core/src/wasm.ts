import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { TenuoConfigurationError } from "./errors.ts";
import type { TenuoErrorCode } from "./api.ts";

export type WasmDecision = {
  outcome: "allow" | "deny" | "approval_required";
  code?: TenuoErrorCode;
  field?: string;
  message?: string;
  args?: Record<string, unknown>;
  tool?: string;
  required?: number;
  received?: number;
};

export type WasmSession = object;

export type WasmContext = {
  mint(allow: unknown, ttlSeconds: number): WasmSession;
  authorize(session: WasmSession, tool: string, args: unknown): WasmDecision;
};

type Generated = {
  SdkContext: new () => WasmContext;
};

let loaded: Generated | undefined;

function generatedPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return join(here, "generated", "tenuo_wasm.js");
}

export function wasmAvailable(): boolean {
  return existsSync(generatedPath());
}

export function loadWasm(): Generated {
  if (loaded) {
    return loaded;
  }
  const path = generatedPath();
  if (!existsSync(path)) {
    throw new TenuoConfigurationError(
      "WASM core is not built. From tenuo-ts run: pnpm build:wasm",
      "TENUO_NOT_READY",
    );
  }
  const require = createRequire(import.meta.url);
  loaded = require(path) as Generated;
  return loaded;
}

export function createDevContext(): WasmContext {
  const { SdkContext } = loadWasm();
  return new SdkContext();
}
