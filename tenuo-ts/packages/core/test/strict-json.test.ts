import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseStrictJson } from "../src/index.ts";

const vector = readFileSync(
  resolve(dirname(fileURLToPath(import.meta.url)), "../../../../tests/vectors/duplicate-argument-keys.json"),
  "utf8",
);

describe("parseStrictJson", () => {
  it("rejects the shared duplicate-key vector", () => {
    expect(() => parseStrictJson(vector)).toThrow(/duplicate JSON key/);
  });

  it("parses an object with unique keys", () => {
    expect(parseStrictJson('{"path":"/data/ok","n":1}')).toEqual({ path: "/data/ok", n: 1 });
  });

  it("rejects a nested duplicate key", () => {
    expect(() => parseStrictJson('{"meta":{"a":1,"a":2}}')).toThrow(/duplicate JSON key/);
  });

  it("keeps __proto__ as an own data property", () => {
    const value = parseStrictJson('{"__proto__":{"admin":true}}') as Record<string, unknown>;
    expect(Object.prototype.hasOwnProperty.call(value, "__proto__")).toBe(true);
    expect(Object.getPrototypeOf(value)).toBe(Object.prototype);
    expect("admin" in value).toBe(false);
    expect(JSON.stringify(value)).toBe('{"__proto__":{"admin":true}}');
    expect("admin" in Object.prototype).toBe(false);
  });

  it("preserves null", () => {
    const value = parseStrictJson('{"a":null}') as { a: unknown };
    expect(value.a).toBeNull();
    expect(JSON.stringify(value)).toBe('{"a":null}');
  });
});
