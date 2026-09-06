#!/usr/bin/env node
/**
 * selfedge theme contract — themes are DATA, not code. Enforced, not promised.
 *
 * A valid theme file contains ONLY:
 *   - comments
 *   - `:root { --var: value; ... }` blocks
 *   - optionally `@media (prefers-color-scheme: light|dark) { :root { ... } }`
 *
 * Nothing else. That means a theme CANNOT:
 *   - add selectors (so it can't hide the honeypot, restyle security UI,
 *     or disappear content)
 *   - fetch anything (`url()` is banned -> no exfiltration beacons, no
 *     third-party fonts sneaking in)
 *   - import anything (`@import` banned)
 *   - smuggle banned tokens via CSS escapes (backslash is banned in values)
 *
 * It also checks COMPLETENESS: every required variable must be defined, so a
 * theme can't silently leave part of the UI unstyled.
 *
 *   node cli/lint-theme.mjs public/css/themes/console.css
 *   node cli/lint-theme.mjs --all          # validate every bundled theme
 */
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

export const REQUIRED_VARS = [
  "bg", "bg-raised", "text", "text-muted",
  "accent", "accent-contrast", "link", "link-hover",
  "border", "focus", "ok", "warn", "danger",
  "font-body", "font-heading", "font-mono",
  "radius", "max-width",
];

const BANNED_IN_VALUES = [
  [/url\s*\(/i, "url() — themes may not reference external resources"],
  [/@import/i, "@import — themes may not import other stylesheets"],
  [/expression\s*\(/i, "expression() — legacy CSS scripting"],
  [/javascript:/i, "javascript: — no script URLs"],
  [/[<>]/, "angle brackets — no markup in values"],
  [/\\/, "backslash — CSS escapes could smuggle banned tokens"],
];

/** Validate theme source text. Returns { ok, problems[], vars: Set } */
export function validateTheme(css) {
  const problems = [];
  const vars = new Set();

  // 1. strip comments
  let rest = css.replace(/\/\*[\s\S]*?\*\//g, " ");

  // 2. extract & validate every allowed block, removing it from `rest`
  const rootBlock = /:root\s*\{([^{}]*)\}/;
  const mediaBlock = /@media\s*\(\s*prefers-color-scheme\s*:\s*(?:light|dark)\s*\)\s*\{\s*(:root\s*\{[^{}]*\})\s*\}/;

  const checkDecls = (inner) => {
    for (const raw of inner.split(";")) {
      const d = raw.trim();
      if (!d) continue;
      const m = d.match(/^--([a-z0-9-]+)\s*:\s*(.+)$/is);
      if (!m) { problems.push(`not a custom-property declaration: "${d.slice(0, 60)}"`); continue; }
      const [, name, value] = m;
      vars.add(name);
      for (const [re, why] of BANNED_IN_VALUES) {
        if (re.test(value)) problems.push(`--${name}: banned content (${why})`);
      }
    }
  };

  let guard = 0;
  for (;;) {
    if (guard++ > 200) { problems.push("too many blocks (malformed file?)"); break; }
    const mMedia = rest.match(mediaBlock);
    if (mMedia) {
      const inner = mMedia[1].match(rootBlock);
      if (inner) checkDecls(inner[1]);
      rest = rest.replace(mediaBlock, " ");
      continue;
    }
    const mRoot = rest.match(rootBlock);
    if (mRoot) { checkDecls(mRoot[1]); rest = rest.replace(rootBlock, " "); continue; }
    break;
  }

  // 3. anything left over is contraband (selectors, at-rules, stray text)
  const leftover = rest.trim();
  if (leftover) problems.push(`disallowed content outside :root blocks: "${leftover.slice(0, 80)}"`);

  // 4. completeness
  const missing = REQUIRED_VARS.filter((v) => !vars.has(v));
  if (missing.length) problems.push(`missing required variables: ${missing.map((v) => "--" + v).join(", ")}`);

  return { ok: problems.length === 0, problems, vars };
}

// ---------------------------------------------------------------- CLI
async function main() {
  const files = process.argv.includes("--all")
    ? (await readdir("public/css/themes")).filter((f) => f.endsWith(".css")).map((f) => join("public/css/themes", f))
    : process.argv.slice(2).filter((a) => a.endsWith(".css"));
  if (files.length === 0) { console.error("usage: lint-theme.mjs <theme.css> | --all"); process.exit(2); }

  let allOk = true;
  for (const f of files) {
    const { ok, problems } = validateTheme(await readFile(f, "utf8"));
    console.log(`${ok ? "✓" : "✗"} ${f}`);
    for (const p of problems) console.log(`    - ${p}`);
    allOk = allOk && ok;
  }
  process.exit(allOk ? 0 : 1);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
