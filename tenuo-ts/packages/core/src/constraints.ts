import type {
  EmailConstraint,
  ExactConstraint,
  MaxConstraint,
  OneOfConstraint,
  PatternConstraint,
  UnderConstraint,
} from "./api.ts";

/** Directory prefix. Evaluated in core as Subpath — not a string prefix check in TS. */
export function under(root: string): UnderConstraint {
  if (!root.startsWith("/")) {
    throw new Error("tenuo.under() expects an absolute path (start with /)");
  }
  return { kind: "under", root };
}

export function email(options: { domain: string }): EmailConstraint {
  return { kind: "email", domain: options.domain };
}

export function max(value: number): MaxConstraint {
  if (!Number.isFinite(value)) {
    throw new Error("tenuo.max() requires a finite number");
  }
  return { kind: "max", value };
}

export function oneOf(values: readonly string[]): OneOfConstraint {
  if (values.length === 0) {
    throw new Error("tenuo.oneOf() requires at least one value");
  }
  return { kind: "oneOf", values };
}

export function pattern(pattern: string): PatternConstraint {
  if (pattern.length === 0) {
    throw new Error("tenuo.pattern() requires a non-empty pattern");
  }
  return { kind: "pattern", pattern };
}

export function exact(value: string | number | boolean): ExactConstraint {
  return { kind: "exact", value };
}
