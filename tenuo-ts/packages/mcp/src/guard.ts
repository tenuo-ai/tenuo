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
  readonly onReceipt?: (receipt: string) => void;
  readonly nonceStore?: NonceStore;
};

/** Official `registerTool` config plus the host ceiling. `allow` is never advertised. */
export type GuardToolConfig = {
  readonly title?: string;
  readonly description?: string;
  readonly inputSchema?: unknown;
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
      authorized = tenuo.mcp.verify(name, asRecord(args), requestMeta(ctx), {
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
    return handler(authorized as TArgs, ctx);
  };
}

/**
 * Register tools on an official `@modelcontextprotocol/server` v2 `McpServer`.
 * Client attach stays `tenuo.mcp.attach()` on `@tenuo/core`.
 */
export function guardTools(tenuo: Tenuo, server: Registerable): {
  register<TArgs extends Record<string, unknown>>(
    name: string,
    config: GuardToolConfig,
    handler: GuardedToolHandler<TArgs>,
  ): unknown;
} {
  return {
    register(name, config, handler) {
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

function isGuardOptions(value: unknown): value is GuardToolOptions {
  if (value === null || typeof value !== "object" || Array.isArray(value) || typeof value === "function") {
    return false;
  }
  const keys = Object.keys(value);
  if (keys.length === 0) {
    return true;
  }
  const known = keys.filter((key) => GUARD_OPTION_KEYS.has(key));
  const unknown = keys.filter((key) => !GUARD_OPTION_KEYS.has(key));
  if (unknown.length > 0 && known.length === 0) {
    throw new TenuoConfigurationError(
      `guardHandler() options have unknown key '${unknown[0]}'. Use allow, onReceipt, or nonceStore.`,
    );
  }
  const record = value as { allow?: unknown; onReceipt?: unknown; nonceStore?: unknown };
  const hasAllow = "allow" in record && record.allow !== null && typeof record.allow === "object";
  const hasReceipt = "onReceipt" in record && typeof record.onReceipt === "function";
  const hasNonce = "nonceStore" in record && record.nonceStore !== null && typeof record.nonceStore === "object";
  return hasAllow || hasReceipt || hasNonce;
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
