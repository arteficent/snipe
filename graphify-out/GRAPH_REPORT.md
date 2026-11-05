# Graph Report - .  (2026-11-05)

## Corpus Check
- 28 files · ~52,575 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1081 nodes · 2121 edges · 58 communities
- Extraction: 94% EXTRACTED · 6% INFERRED · 0% AMBIGUOUS · INFERRED: 137 edges (avg confidence: 0.81)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]
- [[_COMMUNITY_Community 33|Community 33]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 41|Community 41]]
- [[_COMMUNITY_Community 42|Community 42]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 46|Community 46]]
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 48|Community 48]]
- [[_COMMUNITY_Community 50|Community 50]]

## God Nodes (most connected - your core abstractions)
1. `blocking()` - 24 edges
2. `admin_call()` - 21 edges
3. `find()` - 21 edges
4. `remove()` - 20 edges
5. `Result` - 19 edges
6. `String` - 19 edges
7. `env_path()` - 19 edges
8. `Finder` - 18 edges
9. `invoke()` - 18 edges
10. `AppHandle` - 16 edges

## Surprising Connections (you probably didn't know these)
- `Deep Uninstall` --semantically_similar_to--> `Uninstall Pipeline`  [INFERRED] [semantically similar]
  README.md → docs/ARCHITECTURE_AND_PLAN.md
- `Untrusted Software Detection` --semantically_similar_to--> `Untrusted Software Heuristics (implementation status)`  [INFERRED] [semantically similar]
  README.md → docs/ARCHITECTURE_AND_PLAN.md
- `Risk Score (Untrusted & suspicious >= 40)` --semantically_similar_to--> `Leftover Confidence Scoring (0-100)`  [INFERRED] [semantically similar]
  README.md → docs/ARCHITECTURE_AND_PLAN.md
- `Least Privilege / On-demand Elevated Broker` --semantically_similar_to--> `Process & Privilege Model (one binary, two modes)`  [INFERRED] [semantically similar]
  README.md → docs/ARCHITECTURE_AND_PLAN.md
- `Deny-list (Windows paths and registry keys)` --semantically_similar_to--> `Deny-list of Critical Paths and Keys`  [INFERRED] [semantically similar]
  README.md → docs/ARCHITECTURE_AND_PLAN.md

## Import Cycles
- 1-file cycle: `app/src-tauri/src/commands.rs -> app/src-tauri/src/commands.rs`
- 1-file cycle: `crates/snipe-collectors/src/util.rs -> crates/snipe-collectors/src/util.rs`
- 1-file cycle: `crates/snipe-engine/src/safety.rs -> crates/snipe-engine/src/safety.rs`
- 1-file cycle: `crates/snipe-cli/src/main.rs -> crates/snipe-cli/src/main.rs`
- 1-file cycle: `crates/snipe-collectors/src/caches.rs -> crates/snipe-collectors/src/caches.rs`
- 1-file cycle: `crates/snipe-collectors/src/drivers.rs -> crates/snipe-collectors/src/drivers.rs`
- 1-file cycle: `crates/snipe-collectors/src/packages.rs -> crates/snipe-collectors/src/packages.rs`
- 1-file cycle: `crates/snipe-collectors/src/registry.rs -> crates/snipe-collectors/src/registry.rs`
- 1-file cycle: `crates/snipe-collectors/src/sdks.rs -> crates/snipe-collectors/src/sdks.rs`
- 1-file cycle: `crates/snipe-collectors/src/startup.rs -> crates/snipe-collectors/src/startup.rs`
- 1-file cycle: `crates/snipe-collectors/src/tasks.rs -> crates/snipe-collectors/src/tasks.rs`
- 1-file cycle: `crates/snipe-engine/src/engine.rs -> crates/snipe-engine/src/engine.rs`
- 1-file cycle: `crates/snipe-engine/src/broker.rs -> crates/snipe-engine/src/broker.rs`
- 1-file cycle: `crates/snipe-engine/src/cache.rs -> crates/snipe-engine/src/cache.rs`
- 1-file cycle: `crates/snipe-engine/src/export.rs -> crates/snipe-engine/src/export.rs`
- 1-file cycle: `crates/snipe-engine/src/regio.rs -> crates/snipe-engine/src/regio.rs`
- 1-file cycle: `crates/snipe-engine/src/store.rs -> crates/snipe-engine/src/store.rs`
- 1-file cycle: `crates/snipe-engine/src/traces.rs -> crates/snipe-engine/src/traces.rs`
- 1-file cycle: `crates/snipe-engine/src/offline.rs -> crates/snipe-engine/src/offline.rs`

## Communities (58 total, 0 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.09
Nodes (49): AsRef, Drop, Duration, OsStr, Result, String, Drop, ExecOptions (+41 more)

### Community 1 - "Community 1"
Cohesion: 0.05
Nodes (40): @tauri-apps/api/app, dependencies, @tauri-apps/api, devDependencies, svelte, svelte-check, @sveltejs/vite-plugin-svelte, @tauri-apps/cli (+32 more)

### Community 2 - "Community 2"
Cohesion: 0.10
Nodes (48): CleanReport, Item, Leftover, Option, Path, PathBuf, RegPath, Result (+40 more)

### Community 3 - "Community 3"
Cohesion: 0.14
Nodes (48): Engine, ExecOptions, FnMut, FnOnce, Option, PathBuf, Request, Result (+40 more)

### Community 4 - "Community 4"
Cohesion: 0.11
Nodes (35): Collector, CollectResult, Item, Option, PathBuf, String, Vec, Collector (+27 more)

### Community 5 - "Community 5"
Cohesion: 0.13
Nodes (23): HashMap, Item, Leftover, Option, Path, PathBuf, RegKey, RegPath (+15 more)

### Community 6 - "Community 6"
Cohesion: 0.10
Nodes (33): Item, Option, Signature, String, Send, Option, PathBuf, Result (+25 more)

### Community 7 - "Community 7"
Cohesion: 0.09
Nodes (28): Display, Formatter, Into, Option, Result, Self, Signature, String (+20 more)

### Community 8 - "Community 8"
Cohesion: 0.10
Nodes (23): Arch, Collector, CollectResult, Item, Option, RegKey, RegPath, Scope (+15 more)

### Community 9 - "Community 9"
Cohesion: 0.06
Nodes (23): AuthPrompt, CATEGORIES, Category, CleanReport, CollectorInfo, ExecOutcome, KIND_LABELS, Leftover (+15 more)

### Community 10 - "Community 10"
Cohesion: 0.12
Nodes (28): Box, Collector, CollectResult, Duration, Item, ItemKind, Option, Vec (+20 more)

### Community 11 - "Community 11"
Cohesion: 0.15
Nodes (20): ExecOptions, ExecOutcome, FnMut, HashMap, Item, Option, Request, Result (+12 more)

### Community 12 - "Community 12"
Cohesion: 0.07
Nodes (28): app, security, windows, build, beforeBuildCommand, beforeDevCommand, devUrl, frontendDist (+20 more)

### Community 13 - "Community 13"
Cohesion: 0.14
Nodes (22): BufRead, BufReader, Drop, FnMut, Option, Request, Result, ScanEvent (+14 more)

### Community 14 - "Community 14"
Cohesion: 0.13
Nodes (15): Arch, Collector, CollectResult, Item, Option, String, Vec, arch_from() (+7 more)

### Community 15 - "Community 15"
Cohesion: 0.20
Nodes (24): Collector, CollectResult, Item, ItemKind, Option, Path, PathBuf, Scope (+16 more)

### Community 16 - "Community 16"
Cohesion: 0.14
Nodes (25): Item, Option, Secret, String, Vec, AuthPrompt, CleanReport, CollectorInfo (+17 more)

### Community 17 - "Community 17"
Cohesion: 0.10
Nodes (15): Display, Drop, Formatter, Into, Option, Result, Self, String (+7 more)

### Community 18 - "Community 18"
Cohesion: 0.21
Nodes (22): Path, RegKey, RegPath, Result, String, Vec, RegType, delete_key() (+14 more)

### Community 19 - "Community 19"
Cohesion: 0.12
Nodes (18): BSTR, Collector, CollectResult, Drop, FnOnce, Item, Result, String (+10 more)

### Community 20 - "Community 20"
Cohesion: 0.18
Nodes (14): Collector, CollectResult, HashMap, Item, Option, Self, String, Vec (+6 more)

### Community 21 - "Community 21"
Cohesion: 0.20
Nodes (18): clean(), defenderScan(), execute(), exportInventory(), history(), leftovers(), loadCache(), openLocation() (+10 more)

### Community 22 - "Community 22"
Cohesion: 0.16
Nodes (13): Collector, CollectResult, Drop, Item, Option, String, Vec, ENUM_SERVICE_STATUS_PROCESSW (+5 more)

### Community 23 - "Community 23"
Cohesion: 0.18
Nodes (13): Collector, CollectResult, Item, Option, RegKey, Scope, String, Vec (+5 more)

### Community 24 - "Community 24"
Cohesion: 0.21
Nodes (17): Option, Path, PathBuf, RegKey, String, Vec, PSID, account_from_psid() (+9 more)

### Community 25 - "Community 25"
Cohesion: 0.15
Nodes (12): Collector, CollectResult, Drop, Item, Option, String, Vec, PROCESSENTRY32W (+4 more)

### Community 26 - "Community 26"
Cohesion: 0.21
Nodes (15): bump(), [command, arg], commitsSince(), compare(), current(), detectBump(), file(), git() (+7 more)

### Community 27 - "Community 27"
Cohesion: 0.29
Nodes (13): Option, String, Vec, denied_exact(), denied_trees(), env_dir(), is_denied_key(), is_denied_path() (+5 more)

### Community 28 - "Community 28"
Cohesion: 0.21
Nodes (12): Filters, matchesFilters(), matchesRisk(), Arch, Item, ItemKind, Protection, PROTECTIONS (+4 more)

### Community 29 - "Community 29"
Cohesion: 0.31
Nodes (13): ItemKind, Option, String, Vec, assess(), flags_encoded_powershell_and_double_extensions(), flags_unsigned_masquerading_autostart(), is_autostart() (+5 more)

### Community 30 - "Community 30"
Cohesion: 0.26
Nodes (9): Option, String, exe_from_command(), expand(), is_under(), is_windows_path(), normalize(), parent_dir() (+1 more)

### Community 31 - "Community 31"
Cohesion: 0.20
Nodes (8): Collector, CollectResult, Item, Result, Vec, Package, AppxCollector, read_package()

### Community 32 - "Community 32"
Cohesion: 0.21
Nodes (8): Collector, CollectResult, Item, Option, PathBuf, Vec, CachesCollector, candidates()

### Community 33 - "Community 33"
Cohesion: 0.48
Nodes (11): Result, String, bitlocker_protected(), delete_boot_entry(), reboot_now(), register_agent(), resume_bitlocker(), set_one_time_safeboot() (+3 more)

### Community 34 - "Community 34"
Cohesion: 0.26
Nodes (12): Leftover Confidence Scoring (0-100), Untrusted Software Heuristics (implementation status), Authenticode Verification (offline, embedded + catalogs), Deep Uninstall, Scan with Microsoft Defender, Risk Score (Untrusted & suspicious >= 40), Snipe (README), snipe-cli (headless CLI) (+4 more)

### Community 35 - "Community 35"
Cohesion: 0.17
Nodes (10): affected, changed, everything, flags, GLOBAL, mergeBase, meta, names (+2 more)

### Community 36 - "Community 36"
Cohesion: 0.18
Nodes (10): compilerOptions, module, moduleResolution, noEmit, skipLibCheck, strict, target, types (+2 more)

### Community 37 - "Community 37"
Cohesion: 0.38
Nodes (7): Option, String, civil_from_days(), format_ymd(), from_filetime_ticks(), from_unix_secs(), from_yyyymmdd()

### Community 38 - "Community 38"
Cohesion: 0.36
Nodes (9): Item, Option, PathBuf, Result, Vec, Cached, load(), path() (+1 more)

### Community 39 - "Community 39"
Cohesion: 0.42
Nodes (7): Item, String, T, csv_field(), enum_text(), to_csv(), to_json()

### Community 40 - "Community 40"
Cohesion: 0.25
Nodes (9): Avoid WMI Win32_Product (use MsiEnumProductsEx), Collector Trait, Incremental Refresh via Collector Fingerprints, Inventory Cache (SQLite planned, JSON snapshot implemented), Inventory Engine, Item Unified Data Model, Preflight (protection + dependency check), Protection Levels (Removable/Shared/SystemCritical/Locked) (+1 more)

### Community 41 - "Community 41"
Cohesion: 0.25
Nodes (8): app/index.html, /src/main.ts entry module, Testing Strategy (unit, fixture, Windows Sandbox E2E, benchmarks), UninstallString Parsing (CommandLineToArgvW, no cmd /c), Svelte 5 Frontend (app/), .github/scripts/affected.mjs (change detection), CI Result Aggregate Job, Pull Request CI Workflow

### Community 42 - "Community 42"
Cohesion: 0.36
Nodes (7): Engine, Result, main(), String, ExitCode, run(), scan()

### Community 43 - "Community 43"
Cohesion: 0.29
Nodes (8): Delete-on-Reboot for Locked Files, File Quarantine, Registry .reg Backup, Never Follow Reparse Points, Safety Layer, Transaction Journal and Undo, Quarantine, .reg Backups and Undo History, Remove Threat

### Community 44 - "Community 44"
Cohesion: 0.32
Nodes (8): Forced Removal, Install Tracing via ETW, Job Object for Uninstallers, Leftover (Trace) Scanner, Restart Manager Process Shutdown, System Restore Point (SRSetRestorePoint), Silent Uninstall Switches (Inno /VERYSILENT, NSIS /S, MSI /qn), Uninstall Pipeline

### Community 45 - "Community 45"
Cohesion: 0.29
Nodes (7): Snipe Architecture & Implementation Plan, Implementation Phases 0-6, Process & Privilege Model (one binary, two modes), Rust + Tauri 2 Technology Choice, Slint Alternative UI, Least Privilege / On-demand Elevated Broker, Tauri 2 (WebView2)

### Community 46 - "Community 46"
Cohesion: 0.33
Nodes (7): Conventional Commits, NSIS Installer (x64/x86), Semantic Versioning, scripts/version.mjs, Installer Build Matrix (x86_64 / i686 MSVC), Release Workflow, SHA256SUMS Checksums

### Community 47 - "Community 47"
Cohesion: 0.33
Nodes (6): AsRef, Command, AsRef, OsStr, OsStr, hidden_command()

### Community 48 - "Community 48"
Cohesion: 0.33
Nodes (5): description, identifier, permissions, $schema, windows

### Community 50 - "Community 50"
Cohesion: 0.40
Nodes (5): Elevated Broker Named Pipe (DACL to user SID), Deny-list of Critical Paths and Keys, Item-ID-only Broker Requests, Security Requirements, Deny-list (Windows paths and registry keys)

## Knowledge Gaps
- **258 isolated node(s):** `mergeBase`, `changed`, `GLOBAL`, `everything`, `meta` (+253 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `system32()` connect `Community 0` to `Community 33`, `Community 2`, `Community 5`, `Community 14`, `Community 18`, `Community 24`?**
  _High betweenness centrality (0.098) - this node is a cross-community bridge._
- **Why does `read_text()` connect `Community 4` to `Community 24`, `Community 20`, `Community 5`, `Community 15`?**
  _High betweenness centrality (0.055) - this node is a cross-community bridge._
- **Why does `to_wide()` connect `Community 6` to `Community 0`, `Community 24`, `Community 2`, `Community 13`?**
  _High betweenness centrality (0.052) - this node is a cross-community bridge._
- **Are the 4 inferred relationships involving `find()` (e.g. with `dir_size()` and `loaded_user_sids()`) actually correct?**
  _`find()` has 4 INFERRED edges - model-reasoned connections that need verification._
- **Are the 3 inferred relationships involving `remove()` (e.g. with `is_safe_identifier()` and `norm()`) actually correct?**
  _`remove()` has 3 INFERRED edges - model-reasoned connections that need verification._
- **What connects `mergeBase`, `changed`, `GLOBAL` to the rest of the system?**
  _260 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.08956228956228957 - nodes in this community are weakly interconnected._