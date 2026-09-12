import { afterEach, describe, expect, it, vi } from "vitest";
import { memoryNonceStore, TenuoConfigurationError } from "../src/index.ts";

afterEach(() => {
  vi.useRealTimers();
});

describe("memoryNonceStore", () => {
  it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, Number.MAX_VALUE])(
    "rejects ttlSeconds=%s at configuration time",
    (ttlSeconds) => {
      expect(() => memoryNonceStore({ ttlSeconds })).toThrow(TenuoConfigurationError);
      expect(() => memoryNonceStore({ ttlSeconds })).toThrow(
        /ttlSeconds must be positive, finite, and representable in milliseconds/,
      );

      try {
        memoryNonceStore({ ttlSeconds });
      } catch (error) {
        expect(error).toMatchObject({ code: "TENUO_CONFIGURATION" });
      }
    },
  );

  it("uses the 180-second default TTL", () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
    const store = memoryNonceStore();

    expect(store.checkAndRecord("signature")).toBe(true);
    expect(store.checkAndRecord("signature")).toBe(false);

    vi.setSystemTime(179_999);
    expect(store.checkAndRecord("signature")).toBe(false);

    vi.setSystemTime(180_000);
    expect(store.checkAndRecord("signature")).toBe(true);
  });

  it("accepts a positive custom TTL and releases the signature at expiry", () => {
    vi.useFakeTimers();
    vi.setSystemTime(10_000);
    const store = memoryNonceStore({ ttlSeconds: 0.25 });

    expect(store.checkAndRecord("signature")).toBe(true);
    expect(store.checkAndRecord("signature")).toBe(false);

    vi.setSystemTime(10_249);
    expect(store.checkAndRecord("signature")).toBe(false);

    vi.setSystemTime(10_250);
    expect(store.checkAndRecord("signature")).toBe(true);
  });
});
