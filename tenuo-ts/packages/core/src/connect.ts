import { TenuoConfigurationError } from "./errors.ts";

const TOKEN_PREFIX = "tenuo_ct_";
const MAX_SUPPORTED_VERSION = 1;
const inspect = Symbol.for("nodejs.util.inspect.custom");

export type ResolveEndpointOptions = {
  /**
   * Caller-supplied origin used only when the token's `e` field is relative
   * (`/v1` or empty after parse). Never read from the environment.
   */
  readonly localBase?: string;
};

/**
 * Parsed `tenuo_ct_…` token. Endpoint is a bare origin after parse
 * (trailing `/v1` stripped) so callers append `/v1/…` themselves.
 */
export class ConnectToken {
  readonly version: number;
  endpoint: string;
  readonly apiKey: string;
  readonly agentId?: string;
  readonly registrationToken?: string;

  constructor(fields: {
    readonly version: number;
    readonly endpoint: string;
    readonly apiKey: string;
    readonly agentId?: string;
    readonly registrationToken?: string;
  }) {
    this.version = fields.version;
    this.endpoint = fields.endpoint;
    this.apiKey = fields.apiKey;
    if (fields.agentId !== undefined) {
      this.agentId = fields.agentId;
    }
    if (fields.registrationToken !== undefined) {
      this.registrationToken = fields.registrationToken;
    }
  }

  /** True when parse left a path-only or empty origin. */
  get needsEndpointBase(): boolean {
    return this.endpoint.length === 0 || this.endpoint.startsWith("/");
  }

  /**
   * Resolve a relative endpoint against `localBase`. Absolute endpoints,
   * including scheme-less hostnames and loopback hosts, are left unchanged.
   * Does not invent `https://` or a localhost default.
   */
  resolveEndpoint(options: ResolveEndpointOptions = {}): this {
    if (!this.needsEndpointBase) {
      return this;
    }
    const origin = normalizeOrigin(options.localBase ?? "");
    if (origin.length === 0 || origin.startsWith("/")) {
      throw new TenuoConfigurationError(
        "Connect token endpoint is relative. Pass resolveEndpoint({ localBase }) with an origin such as https://control.example.com.",
      );
    }
    this.endpoint = origin;
    return this;
  }

  /** Credential-safe JSON view. API and registration secrets are never serialized. */
  toJSON(): {
    readonly version: number;
    readonly endpoint: string;
    readonly agentId?: string;
  } {
    return {
      version: this.version,
      endpoint: this.endpoint,
      ...(this.agentId !== undefined ? { agentId: this.agentId } : {}),
    };
  }

  toString(): string {
    return `TenuoConnectToken(${this.endpoint || "relative endpoint"})`;
  }

  [inspect](): ReturnType<ConnectToken["toJSON"]> {
    return this.toJSON();
  }
}

/**
 * Parse a complete `tenuo_ct_<base64url-json>` token.
 *
 * Accepts padded and unpadded Base64URL. Version must be 1 (omitted `v`
 * defaults to 1). Registration-token aliases: `t`, `r`, `registration_token`.
 * Does not read environment variables.
 */
export function parseConnectToken(rawToken: string): ConnectToken {
  if (typeof rawToken !== "string" || rawToken.trim().length === 0) {
    throw new TenuoConfigurationError(
      "Connect token must be a tenuo_ct_… string. Copy the full token, including the prefix.",
    );
  }
  const token = rawToken.trim();
  if (!token.startsWith(TOKEN_PREFIX)) {
    throw new TenuoConfigurationError(
      `Connect token must start with '${TOKEN_PREFIX}'. This parser does not accept a raw payload.`,
    );
  }
  const encoded = token.slice(TOKEN_PREFIX.length);
  let jsonBytes: Uint8Array;
  try {
    jsonBytes = decodeBase64Url(encoded);
  } catch {
    throw new TenuoConfigurationError(
      "Connect token payload is not valid Base64URL. Generate a new token.",
    );
  }
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(new TextDecoder().decode(jsonBytes)) as Record<string, unknown>;
  } catch {
    throw new TenuoConfigurationError(
      "Connect token payload is not valid JSON. Generate a new token.",
    );
  }
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new TenuoConfigurationError("Connect token payload must be a JSON object.");
  }

  const version = readVersion(payload.v);
  const endpointRaw = readRequiredString(payload.e, "endpoint");
  const apiKey = readRequiredString(payload.k, "apiKey");
  const agentId = readOptionalString(payload.a);
  const registrationToken = readOptionalString(
    payload.t ?? payload.r ?? payload.registration_token,
  );

  return new ConnectToken({
    version,
    endpoint: stripApiSuffix(endpointRaw),
    apiKey,
    ...(agentId !== undefined ? { agentId } : {}),
    ...(registrationToken !== undefined ? { registrationToken } : {}),
  });
}

function readVersion(value: unknown): number {
  if (value === undefined || value === null) {
    return 1;
  }
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new TenuoConfigurationError(
      "Connect token version must be a non-negative integer. This SDK supports version 1.",
    );
  }
  if (value !== MAX_SUPPORTED_VERSION) {
    throw new TenuoConfigurationError(
      `Connect token version ${value} is not supported by this SDK (max: ${MAX_SUPPORTED_VERSION}). Upgrade @tenuo/core to use this token.`,
    );
  }
  return value;
}

function readRequiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TenuoConfigurationError(
      `Connect token is missing required field '${field}'. Generate a new token.`,
    );
  }
  return value;
}

function readOptionalString(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length === 0) {
    return undefined;
  }
  return value;
}

/** Strip trailing slashes and a final `/v1` so callers append `/v1/…` uniformly. */
export function stripApiSuffix(endpoint: string): string {
  let origin = endpoint.trim();
  while (origin.endsWith("/")) {
    origin = origin.slice(0, -1);
  }
  if (origin.endsWith("/v1")) {
    origin = origin.slice(0, -3);
    while (origin.endsWith("/")) {
      origin = origin.slice(0, -1);
    }
  }
  return origin;
}

function normalizeOrigin(base: string): string {
  return stripApiSuffix(base);
}

function decodeBase64Url(encoded: string): Uint8Array {
  const normalized = encoded.replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  const binary = globalThis.atob(normalized + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
