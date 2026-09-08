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
  it("gives diagrams a clean text equivalent and extractable word boundaries", () => {
    const index = readFileSync(join(REPO, "docs", "lab", "index.md"), "utf8");
    const figure = /<figure class="lab-figure">([\s\S]*?)<\/figure>/.exec(index)?.[1];
    expect(figure).toBeDefined();
    expect(figure).toContain('aria-hidden="true" focusable="false"');
    expect(figure).toContain("<figcaption>You ask Travel Agent to book Alice's Cancún trip.");
    // Removing tags without injecting spaces approximates DOM textContent and
    // catches adjacent SVG labels that a crawler would otherwise join.
    const extracted = figure!.replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim();
    expect(extracted).toContain("Alice → Cancún, 3 nights, $1,200 Travel Agent talks to you Flight Agent books the flight");

    const stage5 = readFileSync(join(REPO, "docs", "lab", "stage-5.md"), "utf8");
    const chain = /<figure class="lab-figure">([\s\S]*?)<\/figure>/.exec(stage5)?.[1];
    expect(chain).toBeDefined();
    const chainText = chain!.replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim();
    expect(chainText).toContain("Control plane signed by the control plane signs the trip permission for Travel Agent narrows Travel Agent");
    expect(chain).toContain("Flight Agent narrows it to reservation UA214 for Check-in Agent");
  });

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

  it("keeps the documentation, lab, and explorer footer aligned with the main website", () => {
    const main = readFileSync(join(REPO, "docs", "index.html"), "utf8");
    const docs = readFileSync(join(REPO, "docs", "_layouts", "default.html"), "utf8");
    const explorer = readFileSync(join(REPO, "tenuo-explorer", "src", "App.tsx"), "utf8");
    const explorerCss = readFileSync(join(REPO, "tenuo-explorer", "src", "index.css"), "utf8");

    for (const surface of [main, docs, explorer]) {
      expect(surface).toContain("© 2026 Tenuo");
      expect(surface).toContain(">Docs<");
      expect(surface).toContain(">GitHub<");
      expect(surface).toContain(">Early Access<");
    }

    for (const surface of [main, docs, explorerCss]) {
      expect(surface).toContain("padding: 48px");
      expect(surface).toContain("font-family: 'JetBrains Mono', monospace");
      expect(surface).toContain("font-size: 0.75rem");
      expect(surface).toContain("letter-spacing: 0.04em");
    }
  });

  it("keeps the documentation and challenge header as focused as the main website", () => {
    const main = readFileSync(join(REPO, "docs", "index.html"), "utf8");
    const docs = readFileSync(join(REPO, "docs", "_layouts", "default.html"), "utf8");
    const mainNav = /<nav>([\s\S]*?)<\/nav>/.exec(main)?.[1];
    const docsNav = /<nav class="top-nav">([\s\S]*?)<\/nav>/.exec(docs)?.[1];

    expect(mainNav).toBeDefined();
    expect(docsNav).toBeDefined();
    expect(docsNav?.match(/<a /g)).toHaveLength(5); // brand plus the four main-site links
    for (const label of ["Docs", "Explorer", "GitHub", "Tenuo Cloud"]) {
      expect(mainNav).toContain(`>${label}<`);
      expect(docsNav).toContain(`>${label}<`);
    }
    for (const label of ["OpenAI", "CrewAI", "LangChain", "Temporal", "Google ADK"]) {
      expect(docsNav).not.toContain(`>${label}<`);
    }
    expect(docs).toContain("@media (max-width: 480px)");
  });
});
