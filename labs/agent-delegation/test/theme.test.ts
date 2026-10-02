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

/** Collect text nodes in source order without treating this as HTML sanitization. */
function textContent(source: string): string {
  return Array.from(source.matchAll(/>([^<]+)</g), (match) => match[1])
    .join("")
    .replace(/\s+/g, " ")
    .trim();
}

describe("public-site theme", () => {
  it("gives diagrams a clean text equivalent and extractable word boundaries", () => {
    const index = readFileSync(join(REPO, "docs", "lab", "index.md"), "utf8");
    const figure = /<figure class="lab-figure">([\s\S]*?)<\/figure>/.exec(index)?.[1];
    expect(figure).toBeDefined();
    expect(figure).toContain('aria-hidden="true" focusable="false"');
    expect(figure).toContain("<figcaption>You ask Travel Agent to book Alice's Cancún trip.");
    // Joining text nodes with only the whitespace present in the source
    // approximates DOM textContent and catches adjacent SVG labels.
    const extracted = textContent(figure!);
    expect(extracted).toContain("Alice → Cancún, 3 nights, $1,200 Travel Agent talks to you Flight Agent books the flight");

    const stage5 = readFileSync(join(REPO, "docs", "lab", "stage-5.md"), "utf8");
    const chain = /<figure class="lab-figure">([\s\S]*?)<\/figure>/.exec(stage5)?.[1];
    expect(chain).toBeDefined();
    const chainText = textContent(chain!);
    expect(chainText).toContain("Control plane signed by the control plane signs the trip permission for Travel Agent narrows Travel Agent");
    expect(chain).toContain("Flight Agent narrows it to reservation UA214 for Check-in Agent");
  });

  // The public site's own layouts (docs/index.html, _layouts/*) and its deploy
  // workflow live in tenuo-ai/website, which checks them. The lab content and
  // the explorer live here, so they are checked against the site's palette.
  const SITE_PALETTE: Record<string, string> = {
    bg: "#040a0f",
    surface: "#0a1018",
    "surface-2": "#0e1620",
    text: "#c8d8e4",
    "text-bright": "#e8e8e8",
    accent: "#38bdf8",
    accent2: "#a855f7",
    green: "#00ff88",
    red: "#ff4466",
    gold: "#c8a96e",
  };

  it("keeps the explorer on the public-site palette and background", () => {
    const explorer = readFileSync(join(REPO, "tenuo-explorer", "src", "index.css"), "utf8");

    for (const [name, value] of Object.entries(SITE_PALETTE)) {
      expect(token(explorer, name), `explorer --${name}`).toBe(value);
    }

    expect(explorer).toContain("background-size: 48px 48px");
    expect(explorer).toContain(".app-shell");
    expect(explorer).not.toContain("radial-gradient(");
    expect(explorer).not.toContain(".site-glow");
    expect(explorer).not.toContain(".orb-1");
  });

  it("keeps the explorer footer aligned with the public site", () => {
    const explorer = readFileSync(join(REPO, "tenuo-explorer", "src", "App.tsx"), "utf8");
    const explorerCss = readFileSync(join(REPO, "tenuo-explorer", "src", "index.css"), "utf8");

    expect(explorer).toContain("© 2026 Tenuo");
    expect(explorer).toContain(">Docs<");
    expect(explorer).toContain(">GitHub<");
    expect(explorer).toContain(">Early Access<");

    expect(explorerCss).toContain("padding: 48px");
    expect(explorerCss).toContain("font-family: 'JetBrains Mono', monospace");
    expect(explorerCss).toContain("font-size: 0.75rem");
    expect(explorerCss).toContain("letter-spacing: 0.04em");
  });
});
