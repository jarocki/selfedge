/**
 * render.mjs — the ONLY path from user content to published HTML.
 *
 * Security model (two independent layers):
 *   1. CONSTRUCTIVE SAFETY — markdown-it runs with html:false, so raw HTML in
 *      markdown is escaped to text, never emitted. Link targets go through
 *      markdown-it's protocol validation (javascript:/vbscript:/file: blocked).
 *      Layouts are fixed templates; every interpolated value is HTML-escaped.
 *   2. VERIFICATION GATE — verifyHtml() inspects the final document and refuses
 *      anything containing script elements, on* handlers, script-URLs, or
 *      dangerous embeds. Publishing calls render() THEN verify(); a verify
 *      failure aborts the publish. Belt and suspenders.
 *
 * The published output contains no inline JS and no inline handlers, so it
 * renders under the site's strict CSP unchanged. That is asserted by tests.
 */
import MarkdownIt from "markdown-it";

const md = new MarkdownIt({
  html: false,        // raw HTML in markdown is ESCAPED, never emitted
  linkify: true,
  typographer: true,
});

// ---------------------------------------------------------------- escaping
export const escapeHtml = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (ch) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));

// ---------------------------------------------------------------- frontmatter
/** Minimal frontmatter: optional leading `--- key: value ... ---` block.
 *  Only `layout` and `title` are recognized; everything else is ignored. */
export function parseFrontmatter(src) {
  const m = String(src).match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/);
  if (!m) return { meta: {}, body: src };
  const meta = {};
  for (const line of m[1].split(/\r?\n/)) {
    const kv = line.match(/^(layout|title)\s*:\s*(.+)$/);
    if (kv) meta[kv[1]] = kv[2].trim();
  }
  return { meta, body: src.slice(m[0].length) };
}

// ---------------------------------------------------------------- layouts
// Fixed, vetted page shells. Content is injected into exactly one slot; all
// site values are escaped. No inline scripts, no inline handlers, ever.
const LAYOUTS = {
  // standard page: header + nav + article + footer
  page: (site, nav, title, contentHtml) => `<!doctype html>
<html lang="${escapeHtml(site.locale || "en")}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} · ${escapeHtml(site.name || "")}</title>
<meta name="description" content="${escapeHtml(site.description || "")}">
<link rel="stylesheet" href="/css/base.css">
<link rel="stylesheet" href="/css/theme.css">
</head>
<body>
<header class="site"><div class="wrap">
  <a class="name" href="/">${escapeHtml(site.name || "")}</a>
  <div class="tagline">${escapeHtml(site.tagline || "")}</div>
  <nav class="site">${nav}</nav>
</div></header>
<main><div class="wrap"><article>
${contentHtml}
</article></div></main>
<footer class="site"><div class="wrap">${escapeHtml(site.name || "")}</div></footer>
</body>
</html>
`,
  // article: same shell, byline slot under the h1 (kept simple for v1)
  article: (site, nav, title, contentHtml) => LAYOUTS.page(site, nav, title, contentHtml),
  // landing: no nav emphasis, content-first
  landing: (site, nav, title, contentHtml) => `<!doctype html>
<html lang="${escapeHtml(site.locale || "en")}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(site.name || "")}</title>
<meta name="description" content="${escapeHtml(site.description || "")}">
<link rel="stylesheet" href="/css/base.css">
<link rel="stylesheet" href="/css/theme.css">
</head>
<body>
<main><div class="wrap"><article>
${contentHtml}
</article><nav class="site">${nav}</nav></div></main>
<footer class="site"><div class="wrap">${escapeHtml(site.name || "")}</div></footer>
</body>
</html>
`,
};
export const LAYOUT_NAMES = Object.keys(LAYOUTS);

function navHtml(site, pages, current) {
  return (pages || [])
    .map((p) => {
      const href = p === "index" ? "/" : `/${escapeHtml(p)}.html`;
      const cur = p === current ? ' aria-current="page"' : "";
      return `<a href="${href}"${cur}>${escapeHtml(p)}</a>`;
    })
    .join("\n  ");
}

// ---------------------------------------------------------------- render
/** markdown (with optional frontmatter) -> full HTML document. */
export function renderPage(markdownSrc, { site = {}, pages = [], pageName = "page" } = {}) {
  const { meta, body } = parseFrontmatter(markdownSrc);
  const layout = LAYOUTS[meta.layout] ? meta.layout : "page";
  const title = meta.title || pageName;
  const contentHtml = md.render(body);
  return LAYOUTS[layout](site, navHtml(site, pages, pageName), title, contentHtml);
}

/** markdown -> body-only HTML (for the preview pane). Same renderer. */
export function renderBody(markdownSrc) {
  const { body } = parseFrontmatter(markdownSrc);
  return md.render(body);
}

// ---------------------------------------------------------------- verify
// The publish gate. Conservative by intent: it inspects the FINAL document and
// rejects anything that could execute or embed active content. False positives
// are acceptable; false negatives are not.
const FORBIDDEN = [
  [/<script\b/i, "a <script> element"],
  [/\bon[a-z]+\s*=/i, "an inline event handler (on…=)"],
  [/javascript\s*:/i, "a javascript: URL"],
  [/vbscript\s*:/i, "a vbscript: URL"],
  [/data\s*:\s*text\/html/i, "a data:text/html URL"],
  [/<iframe\b/i, "an <iframe>"],
  [/<object\b/i, "an <object>"],
  [/<embed\b/i, "an <embed>"],
  [/<base\b/i, "a <base> tag"],
  [/<meta[^>]+http-equiv/i, "a meta refresh/http-equiv"],
  [/<form\b/i, "a raw <form> (forms are provided by the framework, not content)"],
  [/srcdoc\s*=/i, "an srcdoc attribute"],
];

export function verifyHtml(html) {
  const problems = [];
  // Inspect TAG MARKUP ONLY. Strip the text between tags first, so that inert,
  // ESCAPED text — e.g. a post that discusses onerror= or javascript: — is not
  // false-flagged. Real (unescaped) tags and attributes survive this strip and
  // are still caught. This matters: our users write ABOUT these very things.
  const tags = html.replace(/>[^<]*/g, ">");
  for (const [re, what] of FORBIDDEN) {
    if (re.test(tags)) problems.push(`published page would contain ${what}`);
  }
  return { ok: problems.length === 0, problems };
}

/** Render AND gate. Throws if the result would violate the CSP-safety contract. */
export function renderVerified(markdownSrc, opts) {
  const html = renderPage(markdownSrc, opts);
  const { ok, problems } = verifyHtml(html);
  if (!ok) {
    const err = new Error("refusing to publish: " + problems.join("; "));
    err.problems = problems;
    throw err;
  }
  return html;
}
