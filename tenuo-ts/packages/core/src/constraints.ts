import type {
  AllConstraint,
  AnyOfConstraint,
  CelConstraint,
  CidrConstraint,
  ConstraintExpr,
  ContainsConstraint,
  EmailConstraint,
  ExactConstraint,
  MaxConstraint,
  MinConstraint,
  NotConstraint,
  NotOneOfConstraint,
  OneOfConstraint,
  PatternConstraint,
  RangeConstraint,
  RegexConstraint,
  ShlexConstraint,
  SubsetConstraint,
  UnderConstraint,
  UrlPatternConstraint,
  UrlSafeConstraint,
  WildcardConstraint,
} from "./api.ts";
import { TenuoConfigurationError } from "./errors.ts";

/**
 * Builders throw on a misspelled option instead of dropping it: an option
 * that vanishes silently (`urlSafe({ domains })`) widens authority. The core
 * applies the same rule to raw constraint objects when the policy compiles.
 */
function rejectUnknownOptions(
  builder: string,
  options: unknown,
  allowed: readonly string[],
): void {
  if (options === undefined || options === null) {
    return;
  }
  if (typeof options !== "object" || Array.isArray(options)) {
    throw new TenuoConfigurationError(`tenuo.${builder}() expects an options object`);
  }
  const unknown = Object.keys(options).find((key) => !allowed.includes(key));
  if (unknown !== undefined) {
    throw new TenuoConfigurationError(
      `tenuo.${builder}() received unknown option "${unknown}"; allowed options: ${allowed.join(", ")}`,
    );
  }
}

/**
 * Constraint builders. These produce plain marker objects; every one is
 * evaluated by the Rust core, never in TypeScript. The set matches the
 * Python SDK and the core `Constraint` enum one for one. Builders that
 * validate their input throw `TenuoConfigurationError` at the call site.
 * Deeper checks, such as regex syntax, run in the core when `session()`
 * compiles the policy. Nothing here makes an authorization decision.
 */

/** Directory prefix. Evaluated in core as Subpath — not a string prefix check in TS. */
export function under(
  root: string,
  options?: { readonly caseSensitive?: boolean; readonly allowEqual?: boolean },
): UnderConstraint {
  rejectUnknownOptions("under", options, ["caseSensitive", "allowEqual"]);
  if (!root.startsWith("/")) {
    throw new TenuoConfigurationError("tenuo.under() expects an absolute path (start with /)");
  }
  const out: { kind: "under"; root: string; caseSensitive?: boolean; allowEqual?: boolean } = {
    kind: "under",
    root,
  };
  if (options?.caseSensitive !== undefined) {
    out.caseSensitive = options.caseSensitive;
  }
  if (options?.allowEqual !== undefined) {
    out.allowEqual = options.allowEqual;
  }
  return out;
}

export function email(options: { domain: string }): EmailConstraint {
  rejectUnknownOptions("email", options, ["domain"]);
  return { kind: "email", domain: options.domain };
}

export function max(value: number): MaxConstraint {
  if (!Number.isFinite(value)) {
    throw new TenuoConfigurationError("tenuo.max() requires a finite number");
  }
  return { kind: "max", value };
}

export function min(value: number): MinConstraint {
  if (!Number.isFinite(value)) {
    throw new TenuoConfigurationError("tenuo.min() requires a finite number");
  }
  return { kind: "min", value };
}

/** Numeric interval. Bounds are inclusive unless `minExclusive` / `maxExclusive`. */
export function range(options: {
  readonly min?: number;
  readonly max?: number;
  readonly minExclusive?: boolean;
  readonly maxExclusive?: boolean;
}): RangeConstraint {
  rejectUnknownOptions("range", options, ["min", "max", "minExclusive", "maxExclusive"]);
  if (options.min === undefined && options.max === undefined) {
    throw new TenuoConfigurationError("tenuo.range() requires min, max, or both");
  }
  for (const bound of [options.min, options.max]) {
    if (bound !== undefined && !Number.isFinite(bound)) {
      throw new TenuoConfigurationError("tenuo.range() bounds must be finite numbers");
    }
  }
  if (options.min !== undefined && options.max !== undefined && options.min > options.max) {
    throw new TenuoConfigurationError("tenuo.range() min must not exceed max");
  }
  const out: {
    kind: "range";
    min?: number;
    max?: number;
    minExclusive?: boolean;
    maxExclusive?: boolean;
  } = { kind: "range" };
  if (options.min !== undefined) {
    out.min = options.min;
  }
  if (options.max !== undefined) {
    out.max = options.max;
  }
  if (options.minExclusive === true) {
    out.minExclusive = true;
  }
  if (options.maxExclusive === true) {
    out.maxExclusive = true;
  }
  return out;
}

export function oneOf(values: readonly string[]): OneOfConstraint {
  if (values.length === 0) {
    throw new TenuoConfigurationError("tenuo.oneOf() requires at least one value");
  }
  return { kind: "oneOf", values };
}

/** Any value except these. */
export function notOneOf(values: readonly string[]): NotOneOfConstraint {
  if (values.length === 0) {
    throw new TenuoConfigurationError("tenuo.notOneOf() requires at least one value");
  }
  return { kind: "notOneOf", values };
}

/**
 * Generic string glob. `*` matches `/`; this is not path containment.
 * For filesystem arguments, use `pathGlob(root, glob)`.
 */
export function pattern(pattern: string): PatternConstraint {
  if (pattern.length === 0) {
    throw new TenuoConfigurationError("tenuo.pattern() requires a non-empty pattern");
  }
  return { kind: "pattern", pattern };
}

/**
 * A traversal-safe filesystem glob: the value must stay under `root` and
 * match `glob`.
 *
 * The glob is tested against the whole path, not against the part below
 * `root`, so it matches at any depth:
 *
 * ```ts
 * pathGlob("/workspace", "*.json");
 * // /workspace/reports/q3.json  allowed
 * // /workspace/secrets.env      denied (glob)
 * // /etc/passwd.json            denied (root)
 * ```
 *
 * A delegatee can narrow this to a tighter `pathGlob`, or to an `exact()`
 * path the parent already admits.
 */
export function pathGlob(
  root: string,
  glob: string,
  options?: { readonly caseSensitive?: boolean; readonly allowEqual?: boolean },
): AllConstraint {
  return all([under(root, options), pattern(glob)]);
}

/** Regular expression, compiled and evaluated in core. */
export function regex(source: string): RegexConstraint {
  if (source.length === 0) {
    throw new TenuoConfigurationError("tenuo.regex() requires a non-empty expression");
  }
  return { kind: "regex", source };
}

export function exact(value: string | number | boolean): ExactConstraint {
  return { kind: "exact", value };
}

/** Any value at all. Name it in a zero-trust policy to allow an argument without constraining it. */
export function wildcard(): WildcardConstraint {
  return { kind: "wildcard" };
}

/** IP address inside a network, e.g. `cidr("10.0.0.0/8")`. */
export function cidr(network: string): CidrConstraint {
  if (!network.includes("/")) {
    throw new TenuoConfigurationError("tenuo.cidr() expects CIDR notation like 10.0.0.0/8");
  }
  return { kind: "cidr", network };
}

/** URL glob, e.g. `urlPattern("https://*.example.com/api/*")`. Parsed as a URL, not a string. */
export function urlPattern(pattern: string): UrlPatternConstraint {
  if (pattern.length === 0) {
    throw new TenuoConfigurationError("tenuo.urlPattern() requires a non-empty pattern");
  }
  return { kind: "urlPattern", pattern };
}

/**
 * SSRF-aware URL check: http/https only by default, private and link-local
 * hosts rejected, optional allow and deny domain lists (`*.example.com`).
 */
export function urlSafe(options?: {
  readonly schemes?: readonly string[];
  readonly allowDomains?: readonly string[];
  readonly denyDomains?: readonly string[];
}): UrlSafeConstraint {
  rejectUnknownOptions("urlSafe", options, ["schemes", "allowDomains", "denyDomains"]);
  const out: {
    kind: "urlSafe";
    schemes?: readonly string[];
    allowDomains?: readonly string[];
    denyDomains?: readonly string[];
  } = { kind: "urlSafe" };
  if (options?.schemes !== undefined) {
    out.schemes = options.schemes;
  }
  if (options?.allowDomains !== undefined) {
    out.allowDomains = options.allowDomains;
  }
  if (options?.denyDomains !== undefined) {
    out.denyDomains = options.denyDomains;
  }
  return out;
}

/** Shell command whose first word must be one of `allow`. Parsed with shell quoting rules in core. */
export function shlex(allow: readonly string[]): ShlexConstraint {
  if (allow.length === 0) {
    throw new TenuoConfigurationError("tenuo.shlex() requires at least one allowed command");
  }
  return { kind: "shlex", allow };
}

/** List argument that must include every one of these values. */
export function contains(values: readonly (string | number | boolean)[]): ContainsConstraint {
  if (values.length === 0) {
    throw new TenuoConfigurationError("tenuo.contains() requires at least one value");
  }
  return { kind: "contains", values };
}

/** List argument whose every element must be one of these values. */
export function subset(values: readonly (string | number | boolean)[]): SubsetConstraint {
  if (values.length === 0) {
    throw new TenuoConfigurationError("tenuo.subset() requires at least one value");
  }
  return { kind: "subset", values };
}

/** Satisfied when at least one inner constraint is. */
export function anyOf(constraints: readonly ConstraintExpr[]): AnyOfConstraint {
  if (constraints.length === 0) {
    throw new TenuoConfigurationError("tenuo.anyOf() requires at least one constraint");
  }
  return { kind: "anyOf", constraints };
}

/** Satisfied only when every inner constraint is. */
export function all(constraints: readonly ConstraintExpr[]): AllConstraint {
  if (constraints.length === 0) {
    throw new TenuoConfigurationError("tenuo.all() requires at least one constraint");
  }
  return { kind: "all", constraints };
}

/** Satisfied when the inner constraint is not. Delegation cannot narrow a `not`; prefer `notOneOf`. */
export function not(constraint: ConstraintExpr): NotConstraint {
  return { kind: "not", constraint };
}

/** Common Expression Language predicate over the argument value, evaluated in core. */
export function cel(expression: string): CelConstraint {
  if (expression.trim().length === 0) {
    throw new TenuoConfigurationError("tenuo.cel() requires a non-empty expression");
  }
  return { kind: "cel", expression };
}
