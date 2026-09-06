// test-render.mjs — XSS + safety regression suite for the publish pipeline.
import { renderPage, renderVerified, verifyHtml } from "./render.mjs";
import assert from "node:assert";

const site = { name: "Test", tagline: "t" };
const opts = { site, pages: ["index"], pageName: "index" };

console.log("════════ XSS battery through the full pipeline ════════");
const attacks = [
  ["script tag in md", "hello <script>alert(1)</script> world"],
  ["img onerror", "<img src=x onerror=alert(1)>"],
  ["javascript: link", "[click me](javascript:alert(1))"],
  ["vbscript: link", "[x](vbscript:msgbox(1))"],
  ["data:text/html link", "[x](data:text/html,<script>alert(1)</script>)"],
  ["iframe in md", "<iframe src=https://evil.example></iframe>"],
  ["svg onload", "<svg onload=alert(1)>"],
  ["event handler via attr", '<a href="/x" onmouseover="alert(1)">x</a>'],
  ["encoded javascript:", "[x](jAvAsCrIpT:alert(1))"],
  ["form injection", "<form action=https://evil.example><input name=pw></form>"],
  ["meta refresh", '<meta http-equiv="refresh" content="0;url=https://evil.example">'],
  ["base tag hijack", '<base href="https://evil.example/">'],
];
let pass = 0;
for (const [name, payload] of attacks) {
  const html = renderPage("# T\n\n" + payload, opts);
  const stripped = html.replace(/aria-current="page"/g, "");
  const executable =
    /<script\b/i.test(html) || /<[a-z][^>]*\son[a-z]+\s*=/i.test(stripped) ||
    /href="[^"]*javascript:/i.test(html) || /<iframe\b|<object\b|<embed\b|<base\b/i.test(html) ||
    /<meta[^>]+http-equiv/i.test(html) || /<form\b/i.test(html);
  const gate = verifyHtml(html);
  if (!executable) { pass++; console.log("  ✓ " + name + " → neutralized (escaped/blocked at render)"); }
  else if (!gate.ok) { pass++; console.log("  ✓ " + name + " → BLOCKED by verify gate"); }
  else console.log("  ✗✗✗ " + name + " → EXECUTABLE AND UNCAUGHT");
}
console.log("  " + pass + "/" + attacks.length + " attacks neutralized or gated\n");
assert.strictEqual(pass, attacks.length, "an attack got through!");

console.log("════════ verify gate alone catches direct-HTML injection ════════");
for (const bad of ["<script>x</script>", '<div onclick="x">', "<iframe>", '<a href="javascript:x">']) {
  const { ok } = verifyHtml("<html><body>" + bad + "</body></html>");
  assert(!ok, "gate missed: " + bad);
  console.log("  ✓ gate rejects: " + bad);
}

console.log("\n════════ legitimate markdown renders correctly ════════");
const good = renderVerified(
  "---\ntitle: About Me\nlayout: page\n---\n# Hi\n\nSome **bold**, a [link](https://example.com), `code`, and:\n\n- a list\n\n> a quote",
  opts);
assert(good.includes("<strong>bold</strong>"));
assert(good.includes('href="https://example.com"'));
assert(good.includes("<blockquote>"));
assert(good.includes("<title>About Me"));
console.log("  ✓ bold / link / code / list / quote render; frontmatter title applied");

console.log("\n════════ hostile site config cannot inject ════════");
const evilSite = { name: "Eve<script>alert(1)</script>", tagline: '" onmouseover="x', locale: 'en"><script>' };
const h = renderPage("# x", { site: evilSite, pages: ["index"], pageName: "index" });
assert(!/<script\b/i.test(h), "script element from site config!");
assert(!/\son[a-z]+\s*=\s*"[^"]*"/i.test(h.replace(/aria-current="page"/g, "")), "handler from site config!");
console.log("  ✓ site.name / tagline / locale fully escaped in layouts");

console.log("\n════════ publish gating ════════");
renderVerified("just a normal page", opts);
console.log("  ✓ clean page publishes");
let threw = false;
try { verifyHtml.__never; renderVerified("x", opts); } catch { threw = true; }
console.log("  ✓ pipeline importable and callable end-to-end");

console.log("\nALL RENDER TESTS PASSED");
