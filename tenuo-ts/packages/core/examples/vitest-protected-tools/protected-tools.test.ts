/**
 * Consumer recipe: Vitest + protected tools via public APIs only.
 *
 * After installing @tenuo/core, import from that package instead of ../../src/index.ts.
 *
 * From tenuo-ts: pnpm example:vitest-protected-tools
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  AuthorizationDeniedError,
  createTenuo,
  under,
  type Session,
  type Tenuo,
} from "../../src/index.ts";

describe("Vitest recipe: protected tools via public APIs", () => {
  let tenuo: Tenuo;
  let execute: ReturnType<typeof vi.fn<(args: { path: string }) => Promise<string>>>;
  let readFile: { execute: (args: { path: string }) => Promise<string> };
  let session: Session;

  beforeEach(() => {
    // Vitest sets NODE_ENV=test, so createTenuo.devRoot() is allowed.
    tenuo = createTenuo({ root: createTenuo.devRoot() });
    tenuo.ready();

    execute = vi.fn(async ({ path }: { path: string }) => `contents of ${path}`);
    readFile = tenuo.tool(
      { execute },
      {
        capability: "read_file",
        allow: { path: under("/data") },
      },
    );
    session = tenuo.session({ tools: [readFile] });
  });

  afterEach(() => {
    // withSession uses AsyncLocalStorage.run; context ends with the callback.
    vi.clearAllMocks();
  });

  it("allows an in-scope call, invokes the inner tool, and returns its result", async () => {
    const contents = await tenuo.withSession(session, () =>
      readFile.execute({ path: "/data/q3.pdf" }),
    );

    expect(contents).toBe("contents of /data/q3.pdf");
    expect(execute).toHaveBeenCalledOnce();
    expect(execute).toHaveBeenCalledWith({ path: "/data/q3.pdf" });
  });

  it("denies an out-of-scope call without invoking the inner tool", async () => {
    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/etc/passwd" })),
    ).rejects.toMatchObject({
      name: "AuthorizationDeniedError",
      code: "TENUO_CONSTRAINT_VIOLATION",
      field: "path",
    });

    expect(execute).not.toHaveBeenCalled();
  });

  it("asserts denial through stable fields, not the full message text", async () => {
    let caught: unknown;
    try {
      await tenuo.withSession(session, () =>
        readFile.execute({ path: "/etc/passwd" }),
      );
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(AuthorizationDeniedError);
    const denied = caught as AuthorizationDeniedError;
    expect(denied.code).toBe("TENUO_CONSTRAINT_VIOLATION");
    expect(denied.field).toBe("path");
    expect(execute).not.toHaveBeenCalled();
  });
});
