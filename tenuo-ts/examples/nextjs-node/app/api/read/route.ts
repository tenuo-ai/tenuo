import { AuthorizationDeniedError, createTenuo, under } from "@tenuo/core";

export const runtime = "nodejs";

const issuerSecret = createTenuo.generateIssuerKey();
const tenuo = createTenuo({
  root: createTenuo.issuerKeyFromBytes(issuerSecret),
});

const readFile = tenuo.tool(
  {
    execute: async ({ path }: { path: string }) => `contents of ${path}`,
  },
  {
    capability: "read_file",
    allow: { path: under("/data") },
  },
);

const session = tenuo.session({ tools: [readFile], ttlSeconds: 600 });

export async function GET(request: Request) {
  const path = new URL(request.url).searchParams.get("path");
  if (path === null) {
    return Response.json(
      { error: "The path query parameter is required." },
      { status: 400 },
    );
  }

  try {
    const result = await tenuo.withSession(session, () =>
      readFile.execute({ path }),
    );
    return Response.json({ allowed: true, path, result });
  } catch (error) {
    if (error instanceof AuthorizationDeniedError) {
      return Response.json(
        { allowed: false, code: error.code, path },
        { status: 403 },
      );
    }
    throw error;
  }
}
