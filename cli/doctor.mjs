#!/usr/bin/env node
/**
 * selfedge doctor — diagnose a SelfEdge site in plain language.
 *
 * Runs a set of checks and prints what's wrong and how to fix it, in words a
 * non-expert can act on. Checks degrade gracefully: anything needing a live
 * Cloudflare connection is skipped (not failed) when the tools aren't present,
 * so `doctor` is always safe to run and never crashes.
 *
 * The checks are exported individually so the setup wizard can run just the one
 * relevant to a step it just completed ("did that actually work?").
 *
 *   selfedge doctor            # full report
 *   node cli/doctor.mjs        # same, before the CLI is installed
 */
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolveMx, resolveTxt } from "node:dns/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { parse as parseToml } from "smol-toml";

const exec = promisify(execFile);
const TTY = process.stdout.isTTY;
const c = TTY
  ? { g: "\x1b[32m", r: "\x1b[31m", y: "\x1b[33m", b: "\x1b[34m", d: "\x1b[2m", bold: "\x1b[1m", x: "\x1b[0m" }
  : { g: "", r: "", y: "", b: "", d: "", bold: "", x: "" };

// ---- result helpers -------------------------------------------------------
const ok = (detail) => ({ status: "ok", detail });
const fail = (detail, fix) => ({ status: "fail", detail, fix });
const warn = (detail, fix) => ({ status: "warn", detail, fix });
const skip = (detail) => ({ status: "skip", detail });

const GLYPH = { ok: `${c.g}✓${c.x}`, fail: `${c.r}✗${c.x}`, warn: `${c.y}⚠${c.x}`, skip: `${c.d}·${c.x}` };

// ---- shared context (loaded once, passed to every check) ------------------
async function buildContext() {
  const ctx = { config: null, configError: null, hasWrangler: false, secretNames: null };
  try {
    ctx.config = parseToml(await readFile("selfedge.toml", "utf8"));
  } catch (e) {
    ctx.configError = e.code === "ENOENT" ? "missing" : e.message;
  }
  try {
    await exec("wrangler", ["--version"]);
    ctx.hasWrangler = true;
  } catch { /* wrangler not installed / not on PATH */ }
  if (ctx.hasWrangler) {
    try {
      const { stdout } = await exec("wrangler", ["secret", "list", "--format", "json"]);
      ctx.secretNames = new Set(JSON.parse(stdout).map((s) => s.name));
    } catch { /* not logged in, or no worker yet — leave null = unknown */ }
  }
  return ctx;
}

const val = (obj, path) => path.split(".").reduce((o, k) => (o == null ? o : o[k]), obj);
const filled = (v) => typeof v === "string" && v.trim() !== "";

// ---- checks ---------------------------------------------------------------
export const CHECKS = [
  {
    id: "config", group: "Configuration", critical: true,
    run: (ctx) => {
      if (ctx.configError === "missing")
        return fail("No selfedge.toml found.", "Run  selfedge init  to create it, or copy the template.");
      if (ctx.configError)
        return fail(`selfedge.toml couldn't be read: ${ctx.configError}`, "Check the file for a typo (a missing quote or bracket).");
      return ok("Config file found and valid.");
    },
  },
  {
    id: "site-name", group: "Configuration", critical: false,
    run: (ctx) => {
      if (!ctx.config) return skip("no config yet");
      return filled(val(ctx.config, "site.name"))
        ? ok(`Site name: "${val(ctx.config, "site.name")}"`)
        : warn("Your site doesn't have a name yet.", 'Set  name = "Your Name"  under [site] in selfedge.toml.');
    },
  },
  {
    id: "deploy-ids", group: "Configuration", critical: false,
    run: (ctx) => {
      if (!ctx.config) return skip("no config yet");
      const need = ["deploy.domain", "deploy.account_id", "deploy.zone_id"];
      const missing = need.filter((p) => !filled(val(ctx.config, p)));
      if (missing.length === 0) return ok("Cloudflare account and domain are set.");
      return warn(
        `Not ready to go live yet (missing: ${missing.map((m) => m.split(".")[1]).join(", ")}).`,
        "That's fine while you're testing. The setup wizard fills these in when you're ready to deploy.");
    },
  },
  {
    id: "node", group: "Your computer", critical: true,
    run: () => {
      const major = Number(process.version.slice(1).split(".")[0]);
      return major >= 18
        ? ok(`Node ${process.version} (good).`)
        : fail(`Node ${process.version} is too old.`, "Install Node 18 or newer from nodejs.org, then try again.");
    },
  },
  {
    id: "wrangler", group: "Your computer", critical: false,
    run: (ctx) => ctx.hasWrangler
      ? ok("Cloudflare's deploy tool (wrangler) is installed.")
      : warn("The Cloudflare deploy tool isn't installed yet.", "Run  npm install  in this folder — it comes with the project."),
  },
  {
    id: "secret-turnstile", group: "Secrets", critical: false,
    run: (ctx) => secretCheck(ctx, "features.captcha", "turnstile", "deploy.secrets.turnstile_secret", "the human-check (captcha)"),
  },
  {
    id: "secret-alerts", group: "Secrets", critical: false,
    run: (ctx) => {
      if (!ctx.config) return skip("no config yet");
      if (val(ctx.config, "features.alerts") === "none" || !val(ctx.config, "features.alerts")) return skip("alerts off");
      return secretPresent(ctx, "deploy.secrets.alert_webhook_url", "real-time alerts");
    },
  },
  {
    id: "secret-kv", group: "Secrets", critical: false,
    run: (ctx) => {
      if (!ctx.config) return skip("no config yet");
      if (val(ctx.config, "features.intel_sync") !== true) return skip("intel sync off");
      return secretPresent(ctx, "deploy.secrets.kv_write_token", "the daily threat-intel refresh");
    },
  },
  {
    id: "mail", group: "Email safety (checked before any DNS change)", critical: true,
    run: async (ctx) => {
      const domain = ctx.config && val(ctx.config, "deploy.domain");
      if (!filled(domain)) return skip("no domain set yet — nothing to check");
      try {
        const mx = await resolveMx(domain);
        if (!mx || mx.length === 0)
          return fail(`No mail (MX) records found for ${domain}.`,
            "If this domain receives email, DO NOT change nameservers yet. The wizard will not let you proceed until mail is safe.");
        return ok(`Mail records for ${domain} are present (${mx.length} MX). Email won't break.`);
      } catch (e) {
        return warn(`Couldn't look up mail records for ${domain} (${e.code || e.message}).`,
          "Check the domain is spelled right. If it's brand new, this may just mean DNS hasn't been set up yet.");
      }
    },
  },
  {
    id: "spf", group: "Email safety (checked before any DNS change)", critical: false,
    run: async (ctx) => {
      const domain = ctx.config && val(ctx.config, "deploy.domain");
      if (!filled(domain)) return skip("no domain set yet");
      try {
        const txt = (await resolveTxt(domain)).flat().join(" ");
        return /v=spf1/i.test(txt)
          ? ok("Email sender-protection (SPF) record present.")
          : warn("No SPF record found.", "Not fatal, but if you send email from this domain, add one later.");
      } catch { return skip("couldn't read TXT records"); }
    },
  },
  {
    id: "forensics-key", group: "Encrypted archive", critical: false,
    run: async (ctx) => {
      if (!ctx.config || val(ctx.config, "features.forensics") !== true) return skip("forensics off");
      // The private key must NEVER be in the repo. Check .gitignore covers it.
      let ignored = false;
      try { ignored = /priv\.pem|\.jarocki-edge|\.selfedge/.test(await readFile(".gitignore", "utf8")); } catch { /* no gitignore */ }
      if (!ignored)
        return fail("Your private key may not be protected from git.",
          "Add  *.pem  and your key directory to .gitignore before committing. The wizard does this for you.");
      return ok("Private key is excluded from git (good — it must stay offline).");
    },
  },
  {
    id: "theme", group: "Appearance", critical: false,
    run: async (ctx) => {
      if (!ctx.config) return skip("no config yet");
      const name = val(ctx.config, "site.theme");
      if (!filled(name)) return warn("No theme chosen.", 'Set  theme = "console"  under [site] (or paper/terminal/slate).');
      const file = `public/css/themes/${name}.css`;
      if (!existsSync(file))
        return fail(`Theme "${name}" not found (${file}).`, "Pick a bundled theme (console, paper, terminal, slate) or add your own file there.");
      try {
        const { validateTheme } = await import("./lint-theme.mjs");
        const { ok: good, problems } = validateTheme(await readFile(file, "utf8"));
        return good
          ? ok(`Theme "${name}" is valid (pure variables, nothing sneaky).`)
          : fail(`Theme "${name}" breaks the theme contract: ${problems[0]}`,
              "Themes may contain only --variables inside :root. Run  node cli/lint-theme.mjs " + file + "  for the full list.");
      } catch { return skip("theme validator not available"); }
    },
  },
  {
    id: "tripwire", group: "Moving-target defense", critical: false,
    run: (ctx) => {
      if (!ctx.config || val(ctx.config, "moving_target.enabled") !== true) return skip("moving-target off");
      return existsSync("tripwire.json")
        ? ok("Tripwires are generated and in place.")
        : warn("Tripwires haven't been generated yet.", "Run  selfedge spin  to create your unique decoys and canaries.");
    },
  },
];

// ---- secret-check helpers -------------------------------------------------
function secretCheck(ctx, featurePath, featureValue, secretPath, human) {
  if (!ctx.config) return skip("no config yet");
  if (val(ctx.config, featurePath) !== featureValue) return skip(`${featureValue} not selected`);
  return secretPresent(ctx, secretPath, human);
}
function secretPresent(ctx, secretPath, human) {
  const name = val(ctx.config, secretPath);
  if (!filled(name)) return warn(`No secret name configured for ${human}.`, `Set ${secretPath} in selfedge.toml.`);
  if (ctx.secretNames == null)
    return skip(`can't verify ${name} without a Cloudflare login (run  wrangler login)`);
  return ctx.secretNames.has(name)
    ? ok(`Secret for ${human} is set (${name}).`)
    : fail(`The secret for ${human} isn't set yet (${name}).`, `Run  selfedge secret set ${name}`);
}

// ---- runner ---------------------------------------------------------------
async function main() {
  const ctx = await buildContext();
  console.log(`\n${c.bold}SelfEdge doctor${c.x} — checking your site\n`);

  const results = [];
  for (const check of CHECKS) {
    let res;
    try { res = await check.run(ctx); }
    catch (e) { res = warn(`check "${check.id}" errored: ${e.message}`); }
    results.push({ ...check, ...res });
  }

  let lastGroup = null;
  for (const r of results) {
    if (r.status === "skip" && !process.argv.includes("--verbose")) continue;
    if (r.group !== lastGroup) { console.log(`  ${c.d}${r.group}${c.x}`); lastGroup = r.group; }
    console.log(`    ${GLYPH[r.status]} ${r.detail}`);
    if (r.fix) console.log(`        ${c.d}→ ${r.fix}${c.x}`);
  }

  const fails = results.filter((r) => r.status === "fail");
  const warns = results.filter((r) => r.status === "warn");
  const critical = fails.filter((r) => r.critical);
  console.log("");
  if (fails.length === 0 && warns.length === 0) {
    console.log(`  ${c.g}Everything looks good.${c.x}\n`);
  } else if (fails.length > 0) {
    const parts = [`${c.r}${fails.length} to fix${c.x}`];
    if (warns.length) parts.push(`${c.y}${warns.length} heads-up${c.x}`);
    console.log(`  ${parts.join(", ")}. Fix the ${c.r}✗${c.x} items and run  ${c.bold}selfedge doctor${c.x}  again.\n`);
  } else {
    console.log(`  ${c.y}${warns.length} heads-up${c.x} — nothing blocking. Address them when you're ready.\n`);
  }
  process.exit(critical.length > 0 ? 1 : 0);
}

// Run only when invoked directly (so the wizard can import CHECKS without running).
if (import.meta.url === `file://${process.argv[1]}`) main();
