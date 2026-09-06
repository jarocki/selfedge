#!/usr/bin/env node
/**
 * selfedge init — the setup wizard. Plain language, resumable, reversible.
 *
 * Design rules (the security ones are load-bearing):
 *  - RESUMABLE: every step records completion in .selfedge/state.json; re-running
 *    skips what's done. Interrupt it anytime; nothing breaks.
 *  - REVERSIBLE ONLY: init never performs an irreversible action. Going live
 *    (DNS) is a separate, heavily-gated command (`selfedge golive`).
 *  - NO SECRETS AT REST: secret values are prompted with echo off, handed to
 *    wrangler via stdin (never argv — process lists leak argv), and never
 *    written to config, state, or logs.
 *  - NO SHELL: all external commands run via execFile with argument arrays.
 *  - ESCAPED WRITES: anything the user types is escaped before entering
 *    selfedge.toml; themes come from an allowlist; secret names must match
 *    ^[A-Z][A-Z0-9_]*$.
 */
import { mkdir, readFile, writeFile, chmod, appendFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import readline from "node:readline/promises";

const exec = promisify(execFile);
const TTY = process.stdout.isTTY;
const c = TTY
  ? { g: "\x1b[32m", y: "\x1b[33m", b: "\x1b[36m", d: "\x1b[2m", B: "\x1b[1m", x: "\x1b[0m" }
  : { g: "", y: "", b: "", d: "", B: "", x: "" };

const STATE_DIR = ".selfedge";
const STATE_FILE = join(STATE_DIR, "state.json");
const KEY_DIR = join(homedir(), ".selfedge");
const THEMES = ["console", "paper", "terminal", "slate"];

// ---------------------------------------------------------------- utilities
// Buffered line reader: lines are queued as they arrive, so pasted or piped
// input (several answers at once) works instead of racing readline's close.
const rli = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: TTY });
const lineQueue = [];
let lineWaiter = null;
let stdinClosed = false;
rli.on("line", (l) => { if (lineWaiter) { const w = lineWaiter; lineWaiter = null; w(l); } else lineQueue.push(l); });
rli.on("close", () => { stdinClosed = true; if (lineWaiter) { const w = lineWaiter; lineWaiter = null; w(null); } });

async function nextLine(promptText) {
  process.stdout.write(promptText);
  if (lineQueue.length) { const l = lineQueue.shift(); if (!TTY) process.stdout.write("\n"); return l; }
  if (stdinClosed) return null;
  return await new Promise((resolve) => { lineWaiter = resolve; });
}

async function ask(question, { def = "", validate = null } = {}) {
  for (;;) {
    const hint = def ? ` ${c.d}(${def})${c.x}` : "";
    const raw = await nextLine(`  ${question}${hint} `);
    if (raw === null) throw new Error("ran out of answers — run  selfedge init  again to continue");
    const answer = raw.trim() || def;
    if (!validate) return answer;
    const problem = validate(answer);
    if (!problem) return answer;
    console.log(`    ${c.y}${problem}${c.x}`);
  }
}

async function askChoice(question, options, def) {
  const menu = options.map((o, i) => `${i + 1}) ${o.label}`).join("   ");
  for (;;) {
    console.log(`  ${question}`);
    const raw = await nextLine(`    ${menu}  ${c.d}(${def})${c.x} `);
    if (raw === null) throw new Error("ran out of answers — run  selfedge init  again to continue");
    const t = raw.trim();
    if (!t) return def;
    const byNum = options[Number(t) - 1];
    const byVal = options.find((o) => o.value === t.toLowerCase());
    if (byNum) return byNum.value;
    if (byVal) return byVal.value;
    console.log(`    ${c.y}Pick a number 1-${options.length}.${c.x}`);
  }
}

/** Hidden prompt: echo off when TTY; buffered line otherwise (tests/pipes). */
async function askSecret(question) {
  if (!process.stdin.isTTY) {
    const l = await nextLine(`  ${question} `);
    return (l || "").trim();
  }
  process.stdout.write(`  ${question} `);
  return await new Promise((resolve) => {
    const chars = [];
    const onData = (ch) => {
      const s = ch.toString("utf8");
      if (s === "\n" || s === "\r" || s === "\u0004") {
        process.stdin.setRawMode(false);
        process.stdin.removeListener("data", onData);
        process.stdout.write("\n");
        resolve(chars.join("").trim());
      } else if (s === "\u0003") { process.exit(130); }
      else if (s === "\u007f") { chars.pop(); }
      else chars.push(s);
    };
    process.stdin.setRawMode(true);
    process.stdin.on("data", onData);
  });
}

/** Escape a string for a double-quoted TOML value. */
const tomlStr = (s) => `"${String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, " ").replace(/\r/g, "")}"`;
const SECRET_NAME = /^[A-Z][A-Z0-9_]*$/;

async function loadState() {
  try { return JSON.parse(await readFile(STATE_FILE, "utf8")); } catch { return { done: {}, answers: {} }; }
}
async function saveState(state) {
  await mkdir(STATE_DIR, { recursive: true });
  await writeFile(STATE_FILE, JSON.stringify(state, null, 2));
}

async function hasWrangler() {
  try { await exec("wrangler", ["--version"]); return true; } catch { return false; }
}

// ---------------------------------------------------------------- steps
// Each step: { id, title, run(state) } — run() returns notes for the summary.
// Steps are idempotent; completed ones are skipped on resume.

const steps = [
  {
    id: "welcome", title: "Welcome",
    run: async () => {
      console.log(`
  ${c.B}Let's set up your site.${c.x} This takes about ten minutes, asks plain
  questions, and does ${c.B}nothing irreversible${c.x} — you can stop anytime and
  re-run ${c.b}selfedge init${c.x} to pick up where you left off.

  You'll need: a Cloudflare account (free to create). A custom domain is
  optional today — you can add one later with ${c.b}selfedge golive${c.x}.\n`);
      return null;
    },
  },
  {
    id: "identity", title: "Who is this site for?",
    run: async (state) => {
      const a = state.answers;
      a.name = await ask("What's the site called (your name or a project name)?", {
        def: a.name, validate: (v) => (v ? null : "It needs a name — you can change it later."),
      });
      a.tagline = await ask("One line that describes it (shown under the name):", { def: a.tagline || "" });
      a.email = await ask("A public contact email (or leave blank):", {
        def: a.email || "",
        validate: (v) => (!v || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) ? null : "That doesn't look like an email address."),
      });
      a.theme = await askChoice("Pick a look (all simple and fast):",
        THEMES.map((t) => ({ label: t, value: t })), a.theme || "console");
      return `Site: "${a.name}" · theme: ${a.theme}`;
    },
  },
  {
    id: "features", title: "What should your site do?",
    run: async (state) => {
      const a = state.answers;
      console.log(`  ${c.d}Each of these is one plain question. Defaults are sensible.${c.x}`);
      a.alerts = await askChoice(
        "Want a ping (e.g. Discord) when someone probes your site?",
        [{ label: "yes, Discord", value: "discord" }, { label: "no alerts", value: "none" }],
        a.alerts || "discord");
      a.captcha = await askChoice(
        "Add a human-check to your contact form (blocks spam bots)?",
        [{ label: "yes (Cloudflare Turnstile)", value: "turnstile" }, { label: "no", value: "none" }],
        a.captcha || "turnstile");
      a.forensics = await askChoice(
        "Keep an encrypted archive of visits only you can unlock (for investigations)?",
        [{ label: "yes", value: "yes" }, { label: "no", value: "no" }],
        a.forensics || "yes") === "yes";
      a.intel = await askChoice(
        "Refresh threat intelligence daily so alerts name real, current threats?",
        [{ label: "yes", value: "yes" }, { label: "no", value: "no" }],
        a.intel || "yes") === "yes";
      return `alerts: ${a.alerts} · captcha: ${a.captcha} · archive: ${a.forensics ? "on" : "off"} · intel: ${a.intel ? "on" : "off"}`;
    },
  },
  {
    id: "gitignore", title: "Protecting your keys from git",
    run: async () => {
      const lines = ["", "# SelfEdge: never commit keys, secrets, or local state",
        "*.pem", "*.key", ".env", "*.env", "r2.env", ".selfedge/", "tripwire.json", "node_modules/", ""].join("\n");
      let current = "";
      try { current = await readFile(".gitignore", "utf8"); } catch { /* none yet */ }
      if (!current.includes("*.pem")) await appendFile(".gitignore", lines);
      return ".gitignore covers keys, local state, and your tripwires.";
    },
  },
  {
    id: "keypair", title: "Your encryption keys",
    run: async (state) => {
      if (!state.answers.forensics) return "Skipped (encrypted archive is off).";
      const pubFile = join("keys", "public.jwk.json");
      const privFile = join(KEY_DIR, "priv.pem");
      if (existsSync(pubFile) && existsSync(privFile)) return "Keys already exist — kept them.";
      console.log(`  ${c.d}Generating a 4096-bit keypair (a few seconds)…${c.x}`);
      const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 4096 });
      await mkdir(KEY_DIR, { recursive: true, mode: 0o700 });
      await writeFile(privFile, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
      await chmod(privFile, 0o600);
      await mkdir("keys", { recursive: true });
      const jwk = publicKey.export({ format: "jwk" });
      await writeFile(pubFile, JSON.stringify({ ...jwk, alg: "RSA-OAEP-256" }, null, 2));
      console.log(`
  ${c.y}${c.B}Important:${c.x} your ${c.B}private key${c.x} is at ${privFile}
  It is the ONLY way to read your encrypted archive. Copy it somewhere safe
  and offline (a USB drive in a drawer beats any cloud). If you lose it, the
  archive is unreadable forever — by design.\n`);
      return `Public key in repo (${pubFile}); private key offline at ${privFile}.`;
    },
  },
  {
    id: "cloudflare", title: "Connecting to Cloudflare",
    run: async () => {
      if (!(await hasWrangler()))
        return `${c.y}Deferred${c.x} — run  npm install  first, then  selfedge init  again for this step.`;
      try {
        const { stdout } = await exec("wrangler", ["whoami"]);
        const m = stdout.match(/([0-9a-f]{32})/i);
        return m ? `Connected (account ${m[1].slice(0, 6)}…).` : "Connected to Cloudflare.";
      } catch {
        console.log(`  ${c.d}A browser window will open so you can approve access — no tokens to paste.${c.x}`);
        await exec("wrangler", ["login"]);
        return "Connected to Cloudflare.";
      }
    },
  },
  {
    id: "secrets", title: "Setting your secrets",
    run: async (state) => {
      const a = state.answers;
      const wanted = [];
      if (a.alerts === "discord") wanted.push(["ALERT_WEBHOOK_URL", "your Discord webhook URL (channel settings → Integrations → Webhooks)"]);
      if (a.captcha === "turnstile") wanted.push(["TURNSTILE_SECRET", "your Turnstile secret key (Cloudflare dashboard → Turnstile)"]);
      if (wanted.length === 0) return "No secrets needed for your choices.";
      if (!(await hasWrangler()))
        return `${c.y}Deferred${c.x} — after  npm install , run  selfedge init  again and I'll set: ${wanted.map(([n]) => n).join(", ")}.`;
      const set = [];
      for (const [name, help] of wanted) {
        if (!SECRET_NAME.test(name)) continue; // defense in depth
        console.log(`  ${c.d}${help}${c.x}`);
        const value = await askSecret(`Paste ${name} (typing is hidden):`);
        if (!value) { console.log(`    ${c.y}Skipped — set it later with  selfedge secret set ${name}${c.x}`); continue; }
        // stdin, never argv:
        await new Promise((resolve, reject) => {
          const child = execFile("wrangler", ["secret", "put", name], (err) => (err ? reject(err) : resolve()));
          child.stdin.write(value); child.stdin.end();
        });
        set.push(name);
      }
      return set.length ? `Set: ${set.join(", ")}.` : "No secrets set yet (that's okay).";
    },
  },
  {
    id: "write-config", title: "Writing your configuration",
    run: async (state) => {
      const a = state.answers;
      const toml = `# Generated by selfedge init — safe to edit by hand. No secrets live here.

[site]
name        = ${tomlStr(a.name)}
tagline     = ${tomlStr(a.tagline || "")}
description = ${tomlStr(a.tagline || "")}
theme       = ${tomlStr(THEMES.includes(a.theme) ? a.theme : "console")}
locale      = "en"

[site.links]
email = ${tomlStr(a.email || "")}

[content]
pages        = ["index", "about", "contact"]
contact_path = "/contact"

[deploy]
account_id = ""
zone_id    = ""
domain     = ""
site_url   = ""

[deploy.secrets]
cloudflare_api_token = "CLOUDFLARE_API_TOKEN"
alert_webhook_url    = "ALERT_WEBHOOK_URL"
turnstile_secret     = "TURNSTILE_SECRET"
kv_write_token       = "CF_KV_TOKEN"

[features]
captcha    = ${tomlStr(a.captcha)}
alerts     = ${tomlStr(a.alerts)}
intel_sync = ${a.intel === true}
forensics  = ${a.forensics === true}

[forensics]
public_key_file = "keys/public.jwk.json"

[moving_target]
enabled = true
profile = "standard"
freeze  = []
`;
      await writeFile("selfedge.toml", toml);
      return "selfedge.toml written.";
    },
  },
];

// ---------------------------------------------------------------- runner
async function main() {
  const redo = process.argv.includes("--redo");
  const state = await loadState();
  if (redo) state.done = {};

  const resuming = Object.keys(state.done).length > 0;
  console.log(`\n${c.B}SelfEdge setup${c.x}${resuming ? ` ${c.d}— welcome back, picking up where you left off${c.x}` : ""}`);

  for (const step of steps) {
    if (state.done[step.id]) { console.log(`\n${c.g}✓${c.x} ${step.title} ${c.d}(done earlier)${c.x}`); continue; }
    console.log(`\n${c.B}${step.title}${c.x}`);
    const note = await step.run(state);
    if (note) console.log(`  ${c.g}✓${c.x} ${note}`);
    state.done[step.id] = true;
    await saveState(state); // persist after EVERY step -> resumable
  }

  console.log(`
${c.B}Setup complete.${c.x} Next steps, in order:
  1. ${c.b}selfedge doctor${c.x}   — confirm everything is healthy
  2. ${c.b}selfedge spin${c.x}     — generate your unique tripwires
  3. ${c.b}selfedge deploy${c.x}   — put your site on the internet (reversible)
  4. ${c.b}selfedge golive${c.x}   — attach your domain, when you're ready
     ${c.d}(golive checks that your email can't break before it lets you proceed)${c.x}
`);
  rli.close();
}

main().catch((e) => { console.error(`\n${c.y}Setup hit a snag:${c.x} ${e.message}\n${c.d}Nothing is broken — run  selfedge init  again to resume.${c.x}`); rli.close(); process.exit(1); });
