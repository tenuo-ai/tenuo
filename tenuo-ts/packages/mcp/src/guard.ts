import type { AllowPolicy, NonceStore, Tenuo } from "@tenuo/core";
import { TenuoConfigurationError } from "@tenuo/core";

/** Subset of an official v2 `CallToolResult` the adapter returns on deny. */
export type McpToolResult = {
  readonly content?: readonly Record<string, unknown>[];
  readonly structuredContent?: unknown;
  readonly isError?: boolean;
  readonly _meta?: Readonly<Record<string, unknown>>;
};

export type GuardToolOptions = {
  readonly allow?: AllowPolicy;
  readonly onReceipt?: (receipt: string) => void | Promise<void>;
  readonly nonceStore?: NonceStore;
};

/** Infer handler args from a Zod-like schema (`_zod.output` or `_output`). */
export type InferToolArgs<TSchema> = TSchema extends { _zod: { output: infer Output } }
  ? Output extends Record<string, unknown>
    ? Output
    : Record<string, unknown>
  : TSchema extends { _output: infer Output }
    ? Output extends Record<string, unknown>
      ? Output
      : Record<string, unknown>
    : Record<string, unknown>;

/** Official `registerTool` config plus the host ceiling. `allow` is never advertised. */
export type GuardToolConfig<TSchema = unknown> = {
  readonly title?: string;
  readonly description?: string;
  readonly inputSchema?: TSchema;
  readonly outputSchema?: unknown;
  readonly annotations?: unknown;
  readonly icons?: unknown;
  readonly _meta?: Readonly<Record<string, unknown>>;
} & GuardToolOptions;

export type GuardedToolHandler<TArgs extends Record<string, unknown> = Record<string, unknown>> = (
  args: TArgs,
  ctx: unknown,
) => McpToolResult | Promise<McpToolResult>;

type Registerable = {
  registerTool(name: string, config: object, handler: (...args: never[]) => unknown): unknown;
};

const APPLICATION_ERROR_TEXT = "Tool execution failed";

/**
 * Inbound `tools/call` `_meta` from a v2 `ServerContext` (`ctx.mcpReq._meta`).
 * Also accepts the v1 `extra._meta` shape so a recipe handler can reuse this.
 */
export function requestMeta(ctx: unknown): unknown {
  if (ctx === null || typeof ctx !== "object") {
    return undefined;
  }
  const extra = ctx as {
    mcpReq?: { _meta?: unknown };
    _meta?: unknown;
    extra?: { _meta?: unknown };
  };
  return extra.mcpReq?._meta ?? extra._meta ?? extra.extra?._meta;
}

/**
 * Wrap a v2 `registerTool` callback. Verify runs in Rust; the original handler
 * does not run unless the presented warrant and host `allow` both match.
 * Handler exceptions become a sanitized `{ isError: true }` result — the
 * official transport must not see thrown messages.
 */
export function guardHandler<TArgs extends Record<string, unknown>>(
  tenuo: Tenuo,
  name: string,
  handler: GuardedToolHandler<TArgs>,
): (args: TArgs, ctx?: unknown) => Promise<McpToolResult>;
export function guardHandler<TArgs extends Record<string, unknown>>(
  tenuo: Tenuo,
  name: string,
  options: GuardToolOptions,
  handler: GuardedToolHandler<TArgs>,
): (args: TArgs, ctx?: unknown) => Promise<McpToolResult>;
export function guardHandler<TArgs extends Record<string, unknown>>(
  tenuo: Tenuo,
  name: string,
  optionsOrHandler: GuardToolOptions | GuardedToolHandler<TArgs>,
  maybeHandler?: GuardedToolHandler<TArgs>,
): (args: TArgs, ctx?: unknown) => Promise<McpToolResult> {
  const options = isGuardOptions(optionsOrHandler) ? optionsOrHandler : undefined;
  const handler = isGuardOptions(optionsOrHandler) ? maybeHandler : optionsOrHandler;
  if (isTaskHandler(optionsOrHandler) || isTaskHandler(maybeHandler)) {
    throw new TenuoConfigurationError("@tenuo/mcp does not wrap task handlers");
  }
  if (typeof handler !== "function") {
    throw new TenuoConfigurationError("guardHandler() requires a tool handler");
  }
  return async (args, ctx) => {
    let authorized: Record<string, unknown>;
    try {
      authorized = await tenuo.mcp.verify(name, asRecord(args), requestMeta(ctx), {
        ...(options?.allow !== undefined ? { allow: options.allow } : {}),
        ...(options?.onReceipt !== undefined ? { onReceipt: options.onReceipt } : {}),
        ...(options?.nonceStore !== undefined ? { nonceStore: options.nonceStore } : {}),
      });
    } catch (error) {
      return {
        isError: true,
        content: [{ type: "text", text: JSON.stringify(tenuo.mcp.jsonRpcError(error)) }],
      };
    }
    try {
      return await handler(authorized as TArgs, ctx);
    } catch {
      return {
        isError: true,
        content: [{ type: "text", text: APPLICATION_ERROR_TEXT }],
      };
    }
  };
}

/**
 * Register tools on an official `@modelcontextprotocol/server` v2 `McpServer`.
 * Client attach stays `tenuo.mcp.attach()` on `@tenuo/core`.
 */
export function guardTools(tenuo: Tenuo, server: Registerable): {
  register<TSchema>(
    name: string,
    config: GuardToolConfig<TSchema>,
    handler: GuardedToolHandler<InferToolArgs<TSchema>>,
  ): unknown;
} {
  return {
    register(name, config, handler) {
      assertRegisterConfig(config);
      const { allow, onReceipt, nonceStore, ...advertised } = config;
      return server.registerTool(
        name,
        advertised,
        guardHandler(tenuo, name, {
          ...(allow !== undefined ? { allow } : {}),
          ...(onReceipt !== undefined ? { onReceipt } : {}),
          ...(nonceStore !== undefined ? { nonceStore } : {}),
        }, handler) as never,
      );
    },
  };
}

const GUARD_OPTION_KEYS = new Set(["allow", "onReceipt", "nonceStore"]);
const REGISTER_KEYS = new Set([
  "title",
  "description",
  "inputSchema",
  "outputSchema",
  "annotations",
  "icons",
  "_meta",
  "allow",
  "onReceipt",
  "nonceStore",
]);

function assertKnownKeys(value: object, known: ReadonlySet<string>, label: string): void {
  const unknown = Object.keys(value).filter((key) => !known.has(key));
  if (unknown[0] !== undefined) {
    throw new TenuoConfigurationError(
      `${label} has unknown key '${unknown[0]}'. Use ${[...known].join(", ")}.`,
    );
  }
}

function assertRegisterConfig(config: object): void {
  assertKnownKeys(config, REGISTER_KEYS, "guardTools().register() config");
}

function isGuardOptions(value: unknown): value is GuardToolOptions {
  if (value === null || typeof value !== "object" || Array.isArray(value) || typeof value === "function") {
    return false;
  }
  const keys = Object.keys(value);
  assertKnownKeys(value, GUARD_OPTION_KEYS, "guardHandler() options");
  const record = value as { allow?: unknown; onReceipt?: unknown; nonceStore?: unknown };
  const hasAllow = "allow" in record && record.allow !== null && typeof record.allow === "object";
  const hasReceipt = "onReceipt" in record && typeof record.onReceipt === "function";
  const hasNonce = "nonceStore" in record && record.nonceStore !== null && typeof record.nonceStore === "object";
  return keys.length === 0 || hasAllow || hasReceipt || hasNonce;
}

function isTaskHandler(value: unknown): boolean {
  return value !== null && typeof value === "object" && "createTask" in value;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return { ...(value as Record<string, unknown>) };
  }
  return {};
}
