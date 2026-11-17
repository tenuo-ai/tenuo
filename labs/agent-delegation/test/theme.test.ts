import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ROOT } from "../src/state.ts";

const REPO = join(ROOT, "..", "..");

/** Collect text nodes in source order without treating this as HTML sanitization. */
function textContent(source: string): string {
  return Array.from(source.matchAll(/>([^<]+)</g), (match) => match[1])
    .join("")
    .replace(/\s+/g, " ")
    .trim();
}

describe("lab guide accessibility", () => {
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

  // Website layout, palette, and navigation checks belong to tenuo-ai/website.
});
