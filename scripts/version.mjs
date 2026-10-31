#!/usr/bin/env node
// Application versioning. The workspace version in Cargo.toml is the single source of truth;
// this script keeps Cargo.lock and the frontend package files in sync with it.
//
//   node scripts/version.mjs current
//   node scripts/version.mjs next [auto|patch|minor|major]   # next version from conventional commits
//   node scripts/version.mjs set <x.y.z>
//   node scripts/version.mjs notes                           # release notes since the last tag

import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const file = (p) => join(root, p);
const SEMVER = /^(\d+)\.(\d+)\.(\d+)$/;
const MEMBERS = ["snipe", "snipe-core", "snipe-collectors", "snipe-engine", "snipe-cli"];

function git(...args) {
  try {
    return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return "";
  }
}

function current() {
  const toml = readFileSync(file("Cargo.toml"), "utf8");
  const section = toml.split("[workspace.package]")[1] ?? "";
  const match = section.match(/^version\s*=\s*"([^"]+)"/m);
  if (!match) throw new Error("workspace.package.version not found in Cargo.toml");
  return match[1];
}

function lastTag() {
  return git("describe", "--tags", "--abbrev=0", "--match", "v[0-9]*");
}

function commitsSince(tag) {
  const range = tag ? [`${tag}..HEAD`] : [];
  const log = git("log", ...range, "--no-merges", "--format=%s%n%b%x1e");
  return log
    .split("\x1e")
    .map((c) => c.trim())
    .filter(Boolean)
    .filter((c) => !c.startsWith("chore(release)"));
}

function detectBump(commits) {
  if (commits.some((c) => /^\w+(\(.+\))?!:/.test(c) || /BREAKING[ -]CHANGE/.test(c))) return "major";
  if (commits.some((c) => /^feat(\(.+\))?:/.test(c))) return "minor";
  return "patch";
}

function bump(version, level) {
  const [, maj, min, pat] = version.match(SEMVER).map(Number);
  // Before 1.0, breaking changes bump the minor version.
  if (level === "major") return maj === 0 ? `0.${min + 1}.0` : `${maj + 1}.0.0`;
  if (level === "minor") return `${maj}.${min + 1}.0`;
  return `${maj}.${min}.${pat + 1}`;
}

function next(requested = "auto") {
  const version = current();
  const tag = lastTag();
  // First release ships the version already in Cargo.toml.
  if (!tag) return version;
  const commits = commitsSince(tag);
  const level = requested === "auto" ? detectBump(commits) : requested;
  if (!["patch", "minor", "major"].includes(level)) throw new Error(`unknown bump level: ${level}`);
  const base = tag.replace(/^v/, "");
  const candidate = bump(SEMVER.test(base) ? base : version, level);
  // A version raised by hand in Cargo.toml wins over the computed one.
  return compare(version, candidate) > 0 ? version : candidate;
}

function compare(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
}

function replaceOrFail(text, pattern, replacement, what) {
  if (!pattern.test(text)) throw new Error(`could not find ${what}`);
  return text.replace(pattern, replacement);
}

function set(version) {
  if (!SEMVER.test(version)) throw new Error(`not a semantic version: ${version}`);

  const tomlPath = file("Cargo.toml");
  const toml = readFileSync(tomlPath, "utf8");
  const [head, rest] = toml.split("[workspace.package]");
  writeFileSync(
    tomlPath,
    `${head}[workspace.package]${replaceOrFail(rest, /^version\s*=\s*"[^"]+"/m, `version = "${version}"`, "workspace version")}`,
  );

  const lockPath = file("Cargo.lock");
  let lock = readFileSync(lockPath, "utf8");
  for (const name of MEMBERS) {
    lock = lock.replace(
      new RegExp(`(\\[\\[package\\]\\]\\r?\\nname = "${name}"\\r?\\nversion = )"[^"]+"`),
      `$1"${version}"`,
    );
  }
  writeFileSync(lockPath, lock);

  const pkgPath = file("app/package.json");
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
  pkg.version = version;
  writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);

  const pkgLockPath = file("app/package-lock.json");
  const pkgLock = JSON.parse(readFileSync(pkgLockPath, "utf8"));
  pkgLock.version = version;
  if (pkgLock.packages?.[""]) pkgLock.packages[""].version = version;
  writeFileSync(pkgLockPath, `${JSON.stringify(pkgLock, null, 2)}\n`);
}

function notes() {
  const commits = commitsSince(lastTag()).map((c) => c.split("\n")[0]);
  const groups = { Features: [], Fixes: [], Other: [] };
  for (const subject of commits) {
    const key = /^feat/.test(subject) ? "Features" : /^fix/.test(subject) ? "Fixes" : "Other";
    groups[key].push(subject.replace(/^\w+(\(.+?\))?!?:\s*/, ""));
  }
  const sections = Object.entries(groups)
    .filter(([, list]) => list.length > 0)
    .map(([title, list]) => `### ${title}\n\n${list.map((s) => `- ${s}`).join("\n")}`);
  return sections.length > 0 ? sections.join("\n\n") : "Maintenance release.";
}

function output(key, value) {
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${key}=${value}\n`);
}

const [command, arg] = process.argv.slice(2);
try {
  switch (command) {
    case "current":
      console.log(current());
      break;
    case "next": {
      const version = next(arg);
      output("version", version);
      console.log(version);
      break;
    }
    case "set":
      set(arg);
      console.log(`Version set to ${arg}`);
      break;
    case "notes":
      console.log(notes());
      break;
    default:
      console.error("usage: version.mjs current | next [auto|patch|minor|major] | set <x.y.z> | notes");
      process.exit(2);
  }
} catch (e) {
  console.error(e.message);
  process.exit(1);
}
