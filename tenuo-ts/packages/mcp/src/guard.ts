import type { AllowPolicy, NonceStore, Tenuo } from "@tenuo/core";
import { TenuoConfigurationError } from "@tenuo/core";
import type {
  CallToolResult,
  Icon,
  InputRequiredResult,
  McpServer,
  RegisteredTool,
  ServerContext,
  StandardSchemaWithJSON,
  ToolAnnotations,
  ToolCallback,
} from "@modelcontextprotocol/server";

export type McpToolResult = CallToolResult | InputRequiredResult;

export type GuardToolOptions = {
  readonly allow?: AllowPolicy;
  readonly onReceipt?: (receipt: string) => void | Promise<void>;
  readonly nonceStore?: NonceStore;
  readonly onNonceStoreError?: (error: unknown) => void | Promise<void>;
  /**
   * Isolated. Called when the tool handler throws. The client only ever sees
   * "Tool execution failed".
   */
  readonly onHandlerError?: (error: unknown, ctx: GuardCallContext) => void | Promise<void>;
};

/**
 * Enough context for `requestMeta()` and isolated hooks.
 * Official `registerTool` still passes a full `ServerContext`.
 */
export type GuardCallContext = {
  readonly mcpReq?: { readonly _meta?: unknown };
  readonly _meta?: unknown;
  readonly extra?: { readonly _meta?: unknown };
};

/** Infer handler args from an official Standard Schema (Zod v4 included). */
export type InferToolArgs<TSchema> = TSchema extends StandardSchemaWithJSON
  ? StandardSchemaWithJSON.InferOutput<TSchema> extends Record<string, unknown>
    ? StandardSchemaWithJSON.InferOutput<TSchema>
    : Record<string, unknown>
  : Record<string, unknown>;

/** Official `registerTool` config plus the host ceiling. `allow` is never advertised. */
export type GuardToolConfig<TSchema extends StandardSchemaWithJSON | undefined = undefined> = {
  readonly title?: string;
  readonly description?: string;
  readonly inputSchema?: TSchema;
  readonly outputSchema?: StandardSchemaWithJSON;
  readonly annotations?: ToolAnnotations;
  readonly icons?: Icon[];
  readonly _meta?: Readonly<Record<string, unknown>>;
} & GuardToolOptions;

export type GuardedToolHandler<TSchema extends StandardSchemaWithJSON | undefined = undefined> =
  TSchema extends StandardSchemaWithJSON
    ? (
        args: StandardSchemaWithJSON.InferOutput<TSchema>,
        ctx: ServerContext,
      ) => McpToolResult | Promise<McpToolResult>
    : (ctx: ServerContext) => McpToolResult | Promise<McpToolResult>;

/** Low-level `guardHandler` callback. Prefer `guardTools().register()` for schema inference. */
export type GuardHandlerCallback<TArgs extends Record<string, unknown> = Record<string, unknown>> = (
  args: TArgs,
  ctx: GuardCallContext,
) => McpToolResult | Promise<McpToolResult>;

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
 * Low-level `registerTool` wrapper. Infers args from the callback.
 * Schema-typed registration belongs on `guardTools().register()`.
 * Official no-schema tools invoke this as `(ctx)` only; that overload returns
 * `ToolCallback<undefined>` so `registerTool` accepts it without a cast.
 */
export function guardHandler(
  tenuo: Tenuo,
  name: string,
  handler: (ctx: GuardCallContext) => McpToolResult | Promise<McpToolResult>,
): ToolCallback<undefined>;
export function guardHandler(
  tenuo: Tenuo,
  name: string,
  options: GuardToolOptions,
  handler: (ctx: GuardCallContext) => McpToolResult | Promise<McpToolResult>,
): ToolCallback<undefined>;
export function guardHandler<TArgs extends Record<string, unknown>>(
  tenuo: Tenuo,
  name: string,
  handler: GuardHandlerCallback<TArgs>,
): (args: TArgs, ctx?: GuardCallContext) => Promise<McpToolResult>;
export function guardHandler<TArgs extends Record<string, unknown>>(
  tenuo: Tenuo,
  name: string,
  options: GuardToolOptions,
  handler: GuardHandlerCallback<TArgs>,
): (args: TArgs, ctx?: GuardCallContext) => Promise<McpToolResult>;
export function guardHandler<TArgs extends Record<string, unknown>>(
  tenuo: Tenuo,
  name: string,
  optionsOrHandler:
    | GuardToolOptions
    | GuardHandlerCallback<TArgs>
    | ((ctx: GuardCallContext) => McpToolResult | Promise<McpToolResult>),
  maybeHandler?:
    | GuardHandlerCallback<TArgs>
    | ((ctx: GuardCallContext) => McpToolResult | Promise<McpToolResult>),
):
  | ToolCallback<undefined>
  | ((args: TArgs, ctx?: GuardCallContext) => Promise<McpToolResult>) {
  const options = isGuardOptions(optionsOrHandler) ? optionsOrHandler : undefined;
  const handler = isGuardOptions(optionsOrHandler) ? maybeHandler : optionsOrHandler;
  if (isTaskHandler(optionsOrHandler) || isTaskHandler(maybeHandler)) {
    throw new TenuoConfigurationError("@tenuo/mcp does not wrap task handlers");
  }
  if (typeof handler !== "function") {
    throw new TenuoConfigurationError("guardHandler() requires a tool handler");
  }
  return (async (argsOrCtx: unknown, maybeCtx?: unknown) => {
    const ctxOnly = isCtxOnlyCall(argsOrCtx, maybeCtx);
    const args = (ctxOnly ? {} : asRecord(argsOrCtx)) as TArgs;
    const ctx = (ctxOnly ? argsOrCtx : maybeCtx) as GuardCallContext;
    return runGuarded(tenuo, name, options, handler as GuardHandlerCallback, args, ctx, ctxOnly);
  }) as ToolCallback<undefined>;
}

/**
 * Register tools on an official `@modelcontextprotocol/server` v2 `McpServer`.
 * Client attach stays `tenuo.mcp.attach()` on `@tenuo/core`.
 * Tools without `inputSchema` are registered as `(ctx) => …`.
 */
export function guardTools(tenuo: Tenuo, server: Pick<McpServer, "registerTool">): {
  register(name: string, config: GuardToolConfig<undefined>, handler: GuardedToolHandler<undefined>): RegisteredTool;
  register<TSchema extends StandardSchemaWithJSON>(
    name: string,
    config: GuardToolConfig<TSchema>,
    handler: GuardedToolHandler<TSchema>,
  ): RegisteredTool;
} {
  return {
    register(name: string, config: GuardToolConfig<StandardSchemaWithJSON | undefined>, handler: GuardedToolHandler<StandardSchemaWithJSON | undefined>) {
      assertRegisterConfig(config);
      const options = tenuoOptions(config);
      const official = advertisedConfig(config);
      if (config.inputSchema === undefined) {
        return server.registerTool(name, official, async (ctx: ServerContext) =>
          runGuarded(tenuo, name, options, handler, {}, ctx, true),
        );
      }
      return server.registerTool(
        name,
        { ...official, inputSchema: config.inputSchema },
        async (args: unknown, ctx: ServerContext) =>
          runGuarded(tenuo, name, options, handler, asRecord(args), ctx, false),
      );
    },
  };
}

async function runGuarded(
  tenuo: Tenuo,
  name: string,
  options: GuardToolOptions | undefined,
  handler: GuardHandlerCallback | GuardedToolHandler<StandardSchemaWithJSON | undefined>,
  args: Record<string, unknown>,
  ctx: GuardCallContext,
  ctxOnly: boolean,
): Promise<McpToolResult> {
  let authorized: Record<string, unknown>;
  try {
    authorized = await tenuo.mcp.verify(name, args, requestMeta(ctx), {
      ...(options?.allow !== undefined ? { allow: options.allow } : {}),
      ...(options?.onReceipt !== undefined ? { onReceipt: options.onReceipt } : {}),
      ...(options?.nonceStore !== undefined ? { nonceStore: options.nonceStore } : {}),
      ...(options?.onNonceStoreError !== undefined ? { onNonceStoreError: options.onNonceStoreError } : {}),
    });
  } catch (error) {
    return {
      isError: true,
      content: [{ type: "text", text: JSON.stringify(tenuo.mcp.jsonRpcError(error)) }],
    };
  }
  try {
    if (ctxOnly) {
      return await (handler as GuardedToolHandler<undefined>)(ctx as ServerContext);
    }
    return await (handler as GuardHandlerCallback)(authorized, ctx);
  } catch (error) {
    emitHandlerError(options?.onHandlerError, error, ctx);
    return {
      isError: true,
      content: [{ type: "text", text: APPLICATION_ERROR_TEXT }],
    };
  }
}

function emitHandlerError(
  hook: ((error: unknown, ctx: GuardCallContext) => void | Promise<void>) | undefined,
  error: unknown,
  ctx: GuardCallContext,
): void {
  if (hook === undefined) {
    return;
  }
  try {
    const result = hook(error, ctx);
    if (result !== null && typeof result === "object" && "then" in result && typeof result.then === "function") {
      void Promise.resolve(result).catch(() => undefined);
    }
  } catch {
    // Isolated — must not change the public error.
  }
}

function isCtxOnlyCall(argsOrCtx: unknown, maybeCtx: unknown): boolean {
  return maybeCtx === undefined && isServerContext(argsOrCtx);
}

function isServerContext(value: unknown): boolean {
  return value !== null && typeof value === "object" && "mcpReq" in value;
}

const GUARD_OPTION_KEYS = new Set([
  "allow",
  "onReceipt",
  "nonceStore",
  "onNonceStoreError",
  "onHandlerError",
]);
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
  "onNonceStoreError",
  "onHandlerError",
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

function tenuoOptions(config: GuardToolOptions): GuardToolOptions {
  return {
    ...(config.allow !== undefined ? { allow: config.allow } : {}),
    ...(config.onReceipt !== undefined ? { onReceipt: config.onReceipt } : {}),
    ...(config.nonceStore !== undefined ? { nonceStore: config.nonceStore } : {}),
    ...(config.onNonceStoreError !== undefined ? { onNonceStoreError: config.onNonceStoreError } : {}),
    ...(config.onHandlerError !== undefined ? { onHandlerError: config.onHandlerError } : {}),
  };
}

function advertisedConfig(config: GuardToolConfig<StandardSchemaWithJSON | undefined>): {
  title?: string;
  description?: string;
  outputSchema?: StandardSchemaWithJSON;
  annotations?: ToolAnnotations;
  icons?: Icon[];
  _meta?: Record<string, unknown>;
} {
  return {
    ...(config.title !== undefined ? { title: config.title } : {}),
    ...(config.description !== undefined ? { description: config.description } : {}),
    ...(config.outputSchema !== undefined ? { outputSchema: config.outputSchema } : {}),
    ...(config.annotations !== undefined ? { annotations: config.annotations } : {}),
    ...(config.icons !== undefined ? { icons: config.icons } : {}),
    ...(config._meta !== undefined ? { _meta: { ...config._meta } } : {}),
  };
}

function isGuardOptions(value: unknown): value is GuardToolOptions {
  if (value === null || typeof value !== "object" || Array.isArray(value) || typeof value === "function") {
    return false;
  }
  const keys = Object.keys(value);
  assertKnownKeys(value, GUARD_OPTION_KEYS, "guardHandler() options");
  const record = value as {
    allow?: unknown;
    onReceipt?: unknown;
    nonceStore?: unknown;
    onNonceStoreError?: unknown;
    onHandlerError?: unknown;
  };
  const hasAllow = "allow" in record && record.allow !== null && typeof record.allow === "object";
  const hasReceipt = "onReceipt" in record && typeof record.onReceipt === "function";
  const hasNonce = "nonceStore" in record && record.nonceStore !== null && typeof record.nonceStore === "object";
  const hasStoreError = "onNonceStoreError" in record && typeof record.onNonceStoreError === "function";
  const hasHandlerError = "onHandlerError" in record && typeof record.onHandlerError === "function";
  return keys.length === 0 || hasAllow || hasReceipt || hasNonce || hasStoreError || hasHandlerError;
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
