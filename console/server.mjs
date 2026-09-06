#!/usr/bin/env node
/**
 * selfedge console — local editor/operator panel. NEVER exposed to the internet.
 *
 *   node console/server.mjs        (prints the access URL with its token)
 *
 * Security properties:
 *  - binds 127.0.0.1 ONLY; a token (env CONSOLE_TOKEN or generated per-run)
 *    gates every page and API call
 *  - page names validated against ^[a-z0-9][a-z0-9-]{0,40}$ — path traversal
 *    is structurally impossible
 *  - console UI ships zero third-party code and runs under its own strict CSP
 *    (script-src 'self'; no inline scripts, no inline handlers — we eat our
 *    own dog food)
 *  - previews are server-rendered by THE SAME pipeline that publishes, served
 *    as short-lived one-time frames whose response CSP forbids all scripts;
 *    the iframe is additionally sandboxed. What you see is what publishes.
 *  - publishing goes through renderVerified(): a page that would violate the
 *    CSP-safety contract is refused with the reasons, never written.
 */
import http from "node:http";
import { readFile, writeFile, readdir, mkdir } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { parse as parseToml } from "smol-toml";
import { renderBody, renderVerified, LAYOUT_NAMES } from "./render.mjs";

const PORT = Number(process.env.PORT || 8787);
const TOKEN = process.env.CONSOLE_TOKEN || randomBytes(16).toString("hex");
const PAGE_NAME = /^[a-z0-9][a-z0-9-]{0,40}$/;
const CONTENT_DIR = "content";
const PUBLIC_DIR = "public";

const CSP =
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
  "frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'";

// short-lived preview frames: id -> { html, exp }
const previews = new Map();
setInterval(() => { const now = Date.now(); for (const [k, v] of previews) if (v.exp < now) previews.delete(k); }, 30_000).unref();

async function siteConfig() {
  try {
    const cfg = parseToml(await readFile("selfedge.toml", "utf8"));
    return { site: cfg.site || {}, pages: (cfg.content && cfg.content.pages) || ["index"] };
  } catch { return { site: { name: "SelfEdge site" }, pages: ["index"] }; }
}

const send = (res, code, body, headers = {}) => {
  res.writeHead(code, { "Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff", ...headers });
  res.end(body);
};
const json = (res, code, obj) => send(res, code, JSON.stringify(obj), { "Content-Type": "application/json" });

async function readBody(req, limit = 512 * 1024) {
  let size = 0; const chunks = [];
  for await (const c of req) { size += c.length; if (size > limit) throw new Error("body too large"); chunks.push(c); }
  return Buffer.concat(chunks).toString("utf8");
}

const authed = (req, url) =>
  req.headers["x-console-token"] === TOKEN || url.searchParams.get("token") === TOKEN;

async function handler(req, res) {
  // Defeat DNS-rebinding: a malicious page can point its own hostname at
  // 127.0.0.1, but the browser still sends that hostname in Host. Only genuine
  // local access uses localhost/127.0.0.1. (The token is the other layer.)
  const host = (req.headers.host || "").split(":")[0];
  if (host !== "127.0.0.1" && host !== "localhost" && host !== "[::1]") {
    return send(res, 403, "this console is local-only");
  }

  const url = new URL(req.url, "http://127.0.0.1");
  const path = url.pathname;

  // ---- unauthenticated: css for preview frames + the editor's own assets ----
  if (req.method === "GET" && (path === "/assets/editor.css" || path === "/assets/editor.js")) {
    const file = path.endsWith(".css") ? "console/editor.css" : "console/editor.js";
    const type = path.endsWith(".css") ? "text/css" : "text/javascript";
    try { return send(res, 200, await readFile(file), { "Content-Type": type }); }
    catch { return send(res, 404, "not found"); }
  }

  // ---- one-time preview frames (id is the credential; script-free by CSP) ----
  if (req.method === "GET" && path.startsWith("/preview-frame/")) {
    const id = path.slice("/preview-frame/".length);
    const p = previews.get(id);
    if (!p || p.exp < Date.now()) return send(res, 404, "preview expired — edit again");
    return send(res, 200, p.html, {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy":
        "default-src 'none'; style-src 'unsafe-inline'; img-src data: https: http:; script-src 'none'",
    });
  }

  // ---- everything else requires the token ----
  if (!authed(req, url)) return send(res, 401, "console token required (check the URL printed at startup)");

  if (req.method === "GET" && path === "/") {
    return send(res, 200, (await readFile("console/editor.html", "utf8")).replace("__TOKEN__", TOKEN),
      { "Content-Type": "text/html; charset=utf-8" });
  }

  if (req.method === "GET" && path === "/api/pages") {
    const { pages } = await siteConfig();
    let files = [];
    try { files = (await readdir(CONTENT_DIR)).filter((f) => f.endsWith(".md")).map((f) => f.slice(0, -3)); } catch { /* none */ }
    const all = [...new Set([...pages, ...files])].filter((p) => PAGE_NAME.test(p));
    return json(res, 200, { pages: all, layouts: LAYOUT_NAMES });
  }

  const pageMatch = path.match(/^\/api\/page\/([^/]+)$/);
  if (pageMatch) {
    const name = pageMatch[1];
    if (!PAGE_NAME.test(name)) return json(res, 400, { error: "invalid page name (letters, numbers, dashes)" });
    const file = join(CONTENT_DIR, name + ".md");
    if (req.method === "GET") {
      try { return json(res, 200, { name, markdown: await readFile(file, "utf8") }); }
      catch { return json(res, 200, { name, markdown: `---\ntitle: ${name}\nlayout: page\n---\n\n# ${name}\n\nWrite here.\n` }); }
    }
    if (req.method === "PUT") {
      await mkdir(CONTENT_DIR, { recursive: true });
      await writeFile(file, await readBody(req));
      return json(res, 200, { saved: name });
    }
  }

  if (req.method === "POST" && path === "/api/preview") {
    const mdSrc = await readBody(req);
    let css = "";
    try {
      css = (await readFile(join(PUBLIC_DIR, "css/base.css"), "utf8")) + "\n" +
            (await readFile(join(PUBLIC_DIR, "css/theme.css"), "utf8").catch(async () =>
              readFile(join(PUBLIC_DIR, "css/themes/console.css"), "utf8")));
    } catch { /* preview still works unstyled */ }
    const body = renderBody(mdSrc);
    const html = `<!doctype html><html><head><meta charset="utf-8"><style>${css}</style></head>` +
                 `<body><main class="wrap"><article>${body}</article></main></body></html>`;
    const id = randomBytes(12).toString("hex");
    previews.set(id, { html, exp: Date.now() + 60_000 });
    return json(res, 200, { frame: "/preview-frame/" + id });
  }

  if (req.method === "POST" && path === "/api/publish") {
    let name;
    try { name = JSON.parse(await readBody(req)).page; } catch { return json(res, 400, { error: "bad request" }); }
    if (!PAGE_NAME.test(String(name || ""))) return json(res, 400, { error: "invalid page name" });
    const { site, pages } = await siteConfig();
    let mdSrc;
    try { mdSrc = await readFile(join(CONTENT_DIR, name + ".md"), "utf8"); }
    catch { return json(res, 404, { error: "page not saved yet" }); }
    try {
      const html = renderVerified(mdSrc, { site, pages, pageName: name });
      await mkdir(PUBLIC_DIR, { recursive: true });
      await writeFile(join(PUBLIC_DIR, name + ".html"), html);
      if (name === "index") await writeFile(join(PUBLIC_DIR, "index.html"), html);
      return json(res, 200, { published: name + ".html" });
    } catch (e) {
      return json(res, 422, { error: "refused to publish", problems: e.problems || [e.message] });
    }
  }

  send(res, 404, "not found");
}

const server = http.createServer((req, res) =>
  handler(req, res).catch((e) => json(res, 500, { error: e.message })));
server.listen(PORT, "127.0.0.1", () => {
  console.log(`\n  SelfEdge console:  http://127.0.0.1:${PORT}/?token=${TOKEN}`);
  console.log(`  (local only — this address works solely on this computer)\n`);
});
