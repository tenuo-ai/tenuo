import { spawnSync } from "node:child_process";

const REPOSITORY = "tenuo-ai/tenuo";
const ENDPOINT = `/user/starred/${REPOSITORY}`;

export interface StarResult {
  readonly ok: boolean;
  readonly message: string;
}

export interface StarCommandResult {
  readonly status: number | null;
  readonly error?: NodeJS.ErrnoException;
}

export type StarRunner = (withoutCodespacesToken: boolean) => StarCommandResult;

function runGh(withoutCodespacesToken: boolean): StarCommandResult {
  const env = { ...process.env };
  if (withoutCodespacesToken) {
    delete env["GH_TOKEN"];
    delete env["GITHUB_TOKEN"];
  }
  const result = spawnSync("gh", ["api", "--method", "PUT", ENDPOINT, "--silent"], {
    env,
    stdio: "ignore",
  });
  return { status: result.status, ...(result.error !== undefined ? { error: result.error } : {}) };
}

/** Star via the GitHub CLI. The PUT is idempotent and only runs on explicit command. */
export function starRepository(
  runner: StarRunner = runGh,
  codespaces = process.env["CODESPACES"] === "true",
): StarResult {
  const first = runner(false);
  if (first.status === 0) {
    return { ok: true, message: `Starred github.com/${REPOSITORY}. Thank you.` };
  }

  // A Codespaces repository token may not have permission to mutate the
  // participant's user-level stars. Prefer an existing personal gh login.
  if (codespaces && first.error?.code !== "ENOENT") {
    const personal = runner(true);
    if (personal.status === 0) {
      return { ok: true, message: `Starred github.com/${REPOSITORY}. Thank you.` };
    }
  }

  if (first.error?.code === "ENOENT") {
    return {
      ok: false,
      message: "GitHub CLI is not installed. Install it from cli.github.com, then run npm run star again.",
    };
  }
  if (codespaces) {
    return {
      ok: false,
      message: "Codespaces needs your personal GitHub CLI login for stars. Run: env -u GH_TOKEN -u GITHUB_TOKEN gh auth login --hostname github.com\nThen run npm run star again.",
    };
  }
  return {
    ok: false,
    message: "GitHub CLI is not authenticated for this action. Run: gh auth login --hostname github.com\nThen run npm run star again.",
  };
}
