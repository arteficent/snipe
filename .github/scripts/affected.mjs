#!/usr/bin/env node
// Works out what a pull request touched so CI only builds and tests that.
// Rust: packages containing changed files plus every workspace package that depends on them.
// Frontend: anything under app/ outside app/src-tauri/.
//
//   node .github/scripts/affected.mjs <base-ref>

import { execFileSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { relative, sep } from "node:path";

const run = (cmd, args) => execFileSync(cmd, args, { encoding: "utf8", maxBuffer: 64 << 20 }).trim();

const base = process.argv[2] ?? "origin/main";
const mergeBase = run("git", ["merge-base", base, "HEAD"]);
const changed = run("git", ["diff", "--name-only", mergeBase, "HEAD"]).split("\n").filter(Boolean);

// Changes here can affect every crate and the frontend build.
const GLOBAL = [/^Cargo\.(toml|lock)$/, /^rust-toolchain/, /^\.cargo\//, /^\.github\/workflows\/pr\.yml$/, /^\.github\/scripts\//];
const everything = changed.some((f) => GLOBAL.some((re) => re.test(f)));

const meta = JSON.parse(run("cargo", ["metadata", "--no-deps", "--format-version", "1"]));
const packages = meta.packages.map((p) => ({
  name: p.name,
  dir: relative(meta.workspace_root, p.manifest_path.replace(/[\\/]Cargo\.toml$/, "")).split(sep).join("/"),
  deps: p.dependencies.filter((d) => d.path).map((d) => d.name),
}));

const affected = new Set();
if (everything) {
  packages.forEach((p) => affected.add(p.name));
} else {
  for (const file of changed) {
    const owner = packages
      .filter((p) => file.startsWith(`${p.dir}/`))
      .sort((a, b) => b.dir.length - a.dir.length)[0];
    if (owner) affected.add(owner.name);
  }
  // Add reverse dependencies until nothing changes.
  let grew = true;
  while (grew) {
    grew = false;
    for (const p of packages) {
      if (!affected.has(p.name) && p.deps.some((d) => affected.has(d))) {
        affected.add(p.name);
        grew = true;
      }
    }
  }
}

const frontend = everything || changed.some((f) => f.startsWith("app/") && !f.startsWith("app/src-tauri/"));
const names = [...affected].sort();
const flags = names.map((n) => `-p ${n}`).join(" ");

const outputs = {
  rust: String(names.length > 0),
  packages: flags,
  app: String(affected.has("snipe")),
  frontend: String(frontend),
};
for (const [k, v] of Object.entries(outputs)) {
  console.log(`${k}=${v}`);
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${k}=${v}\n`);
}

if (process.env.GITHUB_STEP_SUMMARY) {
  const summary = [
    "### Affected by this pull request",
    "",
    `- Changed files: ${changed.length}`,
    `- Rust packages: ${names.length > 0 ? names.map((n) => `\`${n}\``).join(", ") : "none"}`,
    `- Frontend: ${frontend ? "yes" : "no"}`,
    "",
  ].join("\n");
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary);
}
