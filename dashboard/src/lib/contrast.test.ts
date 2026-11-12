import { readFileSync } from "node:fs";
import { join } from "node:path";

import { contrastRatio, luminance, readTokens } from "./contrast";

const tokens = readTokens(readFileSync(join(__dirname, "..", "app", "globals.css"), "utf8"));

describe("WCAG 2.2 AA contrast of design tokens", () => {
  for (const theme of ["light", "dark"] as const) {
    const t = tokens[theme];
    const pairs: Array<[string, string, string, number]> = [
      ["fg", "bg", "body text", 4.5],
      ["fg", "surface", "text on cards", 4.5],
      ["fg", "surface-muted", "text on muted panels", 4.5],
      ["fg-muted", "surface", "secondary text", 4.5],
      ["fg-muted", "bg", "secondary text on page", 4.5],
      ["primary-fg", "primary", "primary button label", 4.5],
      ["primary", "surface", "links and focus ring", 4.5],
      ["success", "surface", "success text", 4.5],
      ["danger", "surface", "error text", 4.5],
      ["warning", "surface", "warning text", 4.5],
      ["info", "surface", "info text", 4.5],
      // WCAG 2.2 SC 1.4.11: boundaries of form controls need 3:1 against adjacent colours
      ["input-border", "surface", "form control boundary", 3],
      ["input-border", "bg", "form control boundary on page", 3],
      ["ring", "bg", "focus indicator", 3],
    ];
    for (const [fg, bg, what, min] of pairs) {
      it(`${theme}: ${what} (${fg} on ${bg}) >= ${min}:1`, () => {
        expect(t[fg]).toBeDefined();
        expect(t[bg]).toBeDefined();
        expect(contrastRatio(t[fg] as string, t[bg] as string)).toBeGreaterThanOrEqual(min);
      });
    }
  }

  it("computes known ratios", () => {
    expect(contrastRatio("#000000", "#ffffff")).toBeCloseTo(21, 5);
    expect(contrastRatio("#ffffff", "#ffffff")).toBeCloseTo(1, 5);
    expect(luminance("ffffff")).toBeCloseTo(1, 5);
    expect(() => luminance("red")).toThrow(/hex/);
  });

  it("returns empty tokens for a missing selector", () => {
    expect(readTokens("body { color: red }")).toEqual({ light: {}, dark: {} });
  });
});
