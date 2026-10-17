import express from "express";
import { AuthorizationDeniedError, createTenuo, under } from "@tenuo/core";

// This example simulates application-side authentication by binding each route
// to one trusted role. Never select session authority from an untrusted query,
// body, or client-controlled header in a production application.
export function createApp() {
  const app = express();
  const executed: string[] = [];
  const tenuo = createTenuo({ root: createTenuo.devRoot() });

  const readFile = tenuo.tool(
    {
      execute: async ({ path }: { path: string }) => {
        executed.push(path);
        return `contents of ${path}`;
      },
    },
    {
      capability: "read_file",
      allow: { path: under("/workspace") },
    },
  );

  function readFor(scope: "reports" | "finance") {
    return async (req: express.Request, res: express.Response) => {
      const path = req.query.path;
      if (typeof path !== "string") {
        res.status(400).json({ error: "A single path query parameter is required." });
        return;
      }

      // A fresh authority is installed at the request boundary, with no
      // process-global active session. The async callback keeps it scoped.
      const session = tenuo.session({
        allow: { read_file: { path: under(`/workspace/${scope}`) } },
        ttlSeconds: 60,
      });

      try {
        const result = await tenuo.withSession(session, async () => {
          await Promise.resolve(); // exercise an asynchronous request boundary
          return readFile.execute({ path });
        });
        res.json({ allowed: true, result });
      } catch (error) {
        if (error instanceof AuthorizationDeniedError) {
          res.status(403).json({ allowed: false, code: error.code });
          return;
        }
        throw error;
      }
    };
  }

  app.get("/reports/read", readFor("reports"));
  app.get("/finance/read", readFor("finance"));
  return { app, executed };
}
