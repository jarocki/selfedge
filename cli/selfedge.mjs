#!/usr/bin/env node
/**
 * selfedge — unified CLI entrypoint.
 *
 * Routes each subcommand to its module. Commands not yet built in this
 * pre-release exit with a clear message rather than pretending to work.
 */
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const cmd = argv[0];
const rest = argv.slice(1);

const BUILT = {
  init:     "cli/init.mjs",
  doctor:   "cli/doctor.mjs",
  spin:     "cli/spin.mjs",
  console:  "console/server.mjs",
};
// `selfedge theme lint <file>` -> lint-theme.mjs
const SUB = {
  theme: { lint: "cli/lint-theme.mjs" },
};

// Planned but not in this pre-release — be honest about it.
const PLANNED = {
  deploy:  "pushes your site + tripwires live (planned for 1.0.0). For now: `npx wrangler deploy`.",
  golive:  "attaches your domain behind a mail-safety gate (planned for 1.0.0).",
  secret:  "stores a named secret via wrangler (planned for 1.0.0). For now: `npx wrangler secret put <NAME>`.",
};

function run(rel, args) {
  const child = spawn(process.execPath, [join(HERE, "..", rel), ...args], { stdio: "inherit" });
  child.on("exit", (code) => process.exit(code ?? 0));
}

function help() {
  console.log(`
  selfedge <command>

  Available now (v0.5.0 pre-release):
    init            set up your site (plain-language wizard)
    doctor          diagnose your setup in plain language
    spin            reshuffle your moving-target tripwires
    console         open the local editor/operator console
    theme lint <f>  validate a theme file against the safety contract

  Planned for 1.0.0 (not yet built):
    deploy · golive · secret

  Docs: README.md · docs/THREAT-MODEL.md · SECURITY.md
  This is PRE-RELEASE software. See README for known security gaps.
`);
}

if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") { help(); process.exit(0); }
if (cmd === "version" || cmd === "--version" || cmd === "-v") { console.log("selfedge 0.5.0 (pre-release)"); process.exit(0); }

if (BUILT[cmd]) { run(BUILT[cmd], rest); }
else if (SUB[cmd] && SUB[cmd][rest[0]]) { run(SUB[cmd][rest[0]], rest.slice(1)); }
else if (PLANNED[cmd]) { console.error(`\n  "${cmd}" — ${PLANNED[cmd]}\n`); process.exit(2); }
else { console.error(`  unknown command: ${cmd}`); help(); process.exit(2); }
