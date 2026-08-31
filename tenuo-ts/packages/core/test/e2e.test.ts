import { describe, expect, it } from "vitest";
import {
  AuthorizationDeniedError,
  createTenuo,
  TenuoConfigurationError,
  under,
} from "../src/index.ts";

describe("consumer e2e", () => {
  it("allows, denies without execute, redacts session, and rejects missing config", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    tenuo.ready();

    let executed = 0;
    const readFile = tenuo.tool(
      {
        execute: async ({ path }: { path: string }) => {
          executed += 1;
          return `ok:${path}`;
        },
      },
      { capability: "read_file", allow: { path: under("/data") } },
    );

    const session = tenuo.session({ tools: [readFile] });
    expect(JSON.stringify(session)).toBe('"[TenuoSession]"');

    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/data/q3.pdf" })),
    ).resolves.toBe("ok:/data/q3.pdf");
    expect(executed).toBe(1);

    executed = 0;
    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/etc/passwd" })),
    ).rejects.toBeInstanceOf(AuthorizationDeniedError);
    expect(executed).toBe(0);

    expect(() => createTenuo({})).toThrow(TenuoConfigurationError);
    await expect(readFile.execute({ path: "/data/q3.pdf" })).rejects.toBeInstanceOf(
      TenuoConfigurationError,
    );
  });
});
