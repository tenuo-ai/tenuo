import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ROOT } from "../src/state.ts";

const REPO = join(ROOT, "..", "..");

function token(source: string, name: string): string {
  const match = source.match(new RegExp(`--${name}:\\s*([^;]+);`));
  expect(match, `missing --${name}`).not.toBeNull();
  return match![1]!.replace(/\s/g, "");
}

describe("public-site theme", () => {
  it("keeps the lab and explorer on the main website palette and background", () => {
    const main = readFileSync(join(REPO, "docs", "index.html"), "utf8");
    const lab = readFileSync(join(REPO, "docs", "_layouts", "lab.html"), "utf8");
    const explorer = readFileSync(join(REPO, "tenuo-explorer", "src", "index.css"), "utf8");

    for (const name of ["bg", "surface", "surface-2", "text", "text-bright", "accent", "accent2", "green", "red", "gold"]) {
      expect(token(lab, name), `lab --${name}`).toBe(token(main, name));
      expect(token(explorer, name), `explorer --${name}`).toBe(token(main, name));
    }

    for (const surface of [lab, explorer]) {
      expect(surface).toContain("background-size: 48px 48px");
      expect(surface).toContain("radial-gradient(ellipse, rgba(56, 189, 248, 0.07)");
    }
    expect(explorer).toContain(".site-grid-bg");
    expect(explorer).toContain(".site-glow");
    expect(explorer).not.toContain(".orb-1");
  });
});
