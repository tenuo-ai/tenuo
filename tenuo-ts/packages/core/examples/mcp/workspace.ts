/** In-memory company workspace the MCP server exposes. Not an authorization check. */

export type SentEmail = {
  readonly to: string;
  readonly subject: string;
  readonly body: string;
};

const INITIAL: ReadonlyArray<readonly [string, string]> = [
  [
    "/workspace/reports/q3-revenue.md",
    [
      "# Q3 revenue",
      "",
      "North America: $4.2M",
      "EMEA: $1.8M",
      "Pipeline coverage: 3.1x",
    ].join("\n"),
  ],
  [
    "/workspace/reports/q3-customers.md",
    ["# Q3 customers", "", "- Acme Health", "- Northwind Logistics", "- Contoso Energy"].join("\n"),
  ],
  ["/workspace/hr/salaries.csv", "name,title,comp\nShould never leave this directory\n"],
];

export function createWorkspace() {
  const files = new Map<string, string>(INITIAL);
  const sent: SentEmail[] = [];

  return {
    list(path: string): string[] {
      const prefix = path.endsWith("/") ? path : `${path}/`;
      const names = new Set<string>();
      for (const file of files.keys()) {
        if (!file.startsWith(prefix)) {
          continue;
        }
        const rest = file.slice(prefix.length);
        const slash = rest.indexOf("/");
        names.add(slash === -1 ? rest : `${rest.slice(0, slash)}/`);
      }
      if (names.size === 0) {
        throw new Error(`not a directory: ${path}`);
      }
      return [...names].sort();
    },
    read(path: string): string {
      const content = files.get(path);
      if (content === undefined) {
        throw new Error(`not found: ${path}`);
      }
      return content;
    },
    write(path: string, content: string): { path: string; bytes: number } {
      files.set(path, content);
      return { path, bytes: content.length };
    },
    send(email: SentEmail): SentEmail {
      sent.push(email);
      return email;
    },
    sent(): readonly SentEmail[] {
      return sent;
    },
  };
}

export type Workspace = ReturnType<typeof createWorkspace>;
