/** WCAG 2.x relative luminance and contrast ratio, used to test the design tokens. */

function channel(value: number): number {
  const c = value / 255;
  return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

export function luminance(hex: string): number {
  const match = /^#?([0-9a-f]{6})$/i.exec(hex.trim());
  if (!match?.[1]) throw new Error(`not a 6-digit hex colour: ${hex}`);
  const n = Number.parseInt(match[1], 16);
  return 0.2126 * channel((n >> 16) & 255) + 0.7152 * channel((n >> 8) & 255) + 0.0722 * channel(n & 255);
}

export function contrastRatio(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

/** Parse the token blocks of globals.css into { light: {...}, dark: {...} }. */
export function readTokens(css: string): { light: Record<string, string>; dark: Record<string, string> } {
  const grab = (selector: string): Record<string, string> => {
    const start = css.indexOf(`${selector} {`);
    if (start === -1) return {};
    const block = css.slice(start, css.indexOf("}", start));
    const out: Record<string, string> = {};
    for (const m of block.matchAll(/--([a-z-]+):\s*(#[0-9a-fA-F]{6})/g)) out[m[1] as string] = m[2] as string;
    return out;
  };
  return { light: grab(":root"), dark: grab(".dark") };
}
