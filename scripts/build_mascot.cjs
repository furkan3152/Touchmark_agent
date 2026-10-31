#!/usr/bin/env node
// Writes the standalone mascot files in public/mascot/ from frontend/mascot.js and mascot.css,
// so the inline and the standalone Punch never drift apart. Run after changing either file:
//   node scripts/build_mascot.cjs          # write the files
//   node scripts/build_mascot.cjs --check  # exit 1 if a file is out of date
"use strict";
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const mascot = require(path.join(root, "frontend", "mascot.js"));
const css = fs.readFileSync(path.join(root, "frontend", "mascot.css"), "utf8")
  .replace(/\/\*[\s\S]*?\*\//g, "").replace(/\s*\n\s*/g, "\n").trim();
const out = path.join(root, "public", "mascot");
const check = process.argv.includes("--check");
const stale = [];
fs.mkdirSync(out, { recursive: true });

const files = mascot.STATES.map((state) => [state, { }])
  .concat([["warning-evidence", { state: "warning", tone: "evidence" }]]);
for (const [name, opts] of files) {
  const svg = mascot.markup(opts.state || name, { ...opts, standalone: true, size: 200 })
    .replace("<defs>", `<style>${css.replace(/]]>/g, "")}</style><defs>`);
  const file = path.join(out, `${name}.svg`);
  const body = `<?xml version="1.0" encoding="UTF-8"?>\n${svg}\n`;
  if (check) {
    if (!fs.existsSync(file) || fs.readFileSync(file, "utf8") !== body) stale.push(`public/mascot/${name}.svg`);
    continue;
  }
  fs.writeFileSync(file, body);
  console.log(`public/mascot/${name}.svg`);
}
if (stale.length) {
  console.error(`Out of date (run node scripts/build_mascot.cjs): ${stale.join(", ")}`);
  process.exit(1);
}
