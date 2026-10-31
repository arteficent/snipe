# Graph Report - .  (2026-10-31)

## Corpus Check
- Corpus is ~36,895 words - fits in a single context window. You may not need a graph.

## Summary
- 974 nodes · 1900 edges · 49 communities
- Extraction: 94% EXTRACTED · 6% INFERRED · 0% AMBIGUOUS · INFERRED: 116 edges (avg confidence: 0.81)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Frontend API & Types|Frontend API & Types]]
- [[_COMMUNITY_Caches & Signature Trust|Caches & Signature Trust]]
- [[_COMMUNITY_Uninstall Execution|Uninstall Execution]]
- [[_COMMUNITY_Safety Transactions|Safety Transactions]]
- [[_COMMUNITY_Tauri Commands|Tauri Commands]]
- [[_COMMUNITY_Svelte UI Components|Svelte UI Components]]
- [[_COMMUNITY_Package Managers & Modules|Package Managers & Modules]]
- [[_COMMUNITY_Leftover Scanner|Leftover Scanner]]
- [[_COMMUNITY_Collector Registry & Tasks|Collector Registry & Tasks]]
- [[_COMMUNITY_Core Item Model|Core Item Model]]
- [[_COMMUNITY_Registry Programs Collector|Registry Programs Collector]]
- [[_COMMUNITY_Elevated Broker IPC|Elevated Broker IPC]]
- [[_COMMUNITY_Engine Request Handler|Engine Request Handler]]
- [[_COMMUNITY_Tauri Configuration|Tauri Configuration]]
- [[_COMMUNITY_Registry IO & Backup|Registry I/O & Backup]]
- [[_COMMUNITY_DISM Features & Updates|DISM Features & Updates]]
- [[_COMMUNITY_SDK & Runtime Detection|SDK & Runtime Detection]]
- [[_COMMUNITY_Driver Packages|Driver Packages]]
- [[_COMMUNITY_Engine Protocol|Engine Protocol]]
- [[_COMMUNITY_Services Collector|Services Collector]]
- [[_COMMUNITY_Startup Entries|Startup Entries]]
- [[_COMMUNITY_Process Collector|Process Collector]]
- [[_COMMUNITY_Versioning Script|Versioning Script]]
- [[_COMMUNITY_Deny-list|Deny-list]]
- [[_COMMUNITY_Risk Heuristics|Risk Heuristics]]
- [[_COMMUNITY_Path Utilities|Path Utilities]]
- [[_COMMUNITY_AppX Packages|AppX Packages]]
- [[_COMMUNITY_Security Features (Docs)|Security Features (Docs)]]
- [[_COMMUNITY_PR Change Detection|PR Change Detection]]
- [[_COMMUNITY_TypeScript Config|TypeScript Config]]
- [[_COMMUNITY_Date Helpers|Date Helpers]]
- [[_COMMUNITY_Inventory Cache|Inventory Cache]]
- [[_COMMUNITY_CSVJSON Export|CSV/JSON Export]]
- [[_COMMUNITY_Secure Data Store|Secure Data Store]]
- [[_COMMUNITY_Inventory Design (Docs)|Inventory Design (Docs)]]
- [[_COMMUNITY_Frontend & PR CI (Docs)|Frontend & PR CI (Docs)]]
- [[_COMMUNITY_CLI Entry Point|CLI Entry Point]]
- [[_COMMUNITY_Safety Layer (Docs)|Safety Layer (Docs)]]
- [[_COMMUNITY_Uninstall Pipeline (Docs)|Uninstall Pipeline (Docs)]]
- [[_COMMUNITY_Architecture & Tech Choice|Architecture & Tech Choice]]
- [[_COMMUNITY_Release & Versioning (Docs)|Release & Versioning (Docs)]]
- [[_COMMUNITY_Tauri Capabilities|Tauri Capabilities]]
- [[_COMMUNITY_Broker Security Model|Broker Security Model]]

## God Nodes (most connected - your core abstractions)
1. `blocking()` - 22 edges
2. `find()` - 21 edges
3. `admin_call()` - 20 edges
4. `env_path()` - 19 edges
5. `Result` - 18 edges
6. `String` - 18 edges
7. `remove()` - 18 edges
8. `Finder` - 18 edges
9. `AppHandle` - 15 edges
10. `Item` - 15 edges

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
- 1-file cycle: `crates/snipe-cli/src/main.rs -> crates/snipe-cli/src/main.rs`
- 1-file cycle: `crates/snipe-collectors/src/caches.rs -> crates/snipe-collectors/src/caches.rs`
- 1-file cycle: `crates/snipe-collectors/src/drivers.rs -> crates/snipe-collectors/src/drivers.rs`
- 1-file cycle: `crates/snipe-collectors/src/packages.rs -> crates/snipe-collectors/src/packages.rs`
- 1-file cycle: `crates/snipe-collectors/src/registry.rs -> crates/snipe-collectors/src/registry.rs`
- 1-file cycle: `crates/snipe-collectors/src/sdks.rs -> crates/snipe-collectors/src/sdks.rs`
- 1-file cycle: `crates/snipe-collectors/src/startup.rs -> crates/snipe-collectors/src/startup.rs`
- 1-file cycle: `crates/snipe-collectors/src/tasks.rs -> crates/snipe-collectors/src/tasks.rs`
- 1-file cycle: `crates/snipe-engine/src/broker.rs -> crates/snipe-engine/src/broker.rs`
- 1-file cycle: `crates/snipe-engine/src/cache.rs -> crates/snipe-engine/src/cache.rs`
- 1-file cycle: `crates/snipe-engine/src/engine.rs -> crates/snipe-engine/src/engine.rs`
- 1-file cycle: `crates/snipe-engine/src/export.rs -> crates/snipe-engine/src/export.rs`
- 1-file cycle: `crates/snipe-engine/src/regio.rs -> crates/snipe-engine/src/regio.rs`
- 1-file cycle: `crates/snipe-engine/src/safety.rs -> crates/snipe-engine/src/safety.rs`
- 1-file cycle: `crates/snipe-engine/src/store.rs -> crates/snipe-engine/src/store.rs`
- 1-file cycle: `crates/snipe-engine/src/traces.rs -> crates/snipe-engine/src/traces.rs`

## Hyperedges (group relationships)
- **Broker-driven uninstall flow: broker -> safety -> uninstall -> leftover scan -> backup/quarantine** — docs_architecture_and_plan_broker_named_pipe, docs_architecture_and_plan_safety_layer, docs_architecture_and_plan_uninstall_pipeline, docs_architecture_and_plan_leftover_scanner, docs_architecture_and_plan_file_quarantine, docs_architecture_and_plan_registry_backup [EXTRACTED 1.00]
- **Versioning and release pipeline** — readme_version_mjs, readme_conventional_commits, readme_semantic_versioning, workflows_release_release_workflow, workflows_release_installer_build_matrix, readme_nsis_installer [EXTRACTED 1.00]
- **Untrusted software detection and response** — readme_authenticode_verification, readme_risk_score, readme_remove_threat, readme_defender_scan, readme_quarantine_and_undo [EXTRACTED 1.00]

## Communities (49 total, 0 thin omitted)

### Community 0 - "Frontend API & Types"
Cohesion: 0.05
Nodes (32): Filters, matchesFilters(), matchesRisk(), Arch, CATEGORIES, Category, CleanReport, CollectorInfo (+24 more)

### Community 1 - "Caches & Signature Trust"
Cohesion: 0.07
Nodes (45): Collector, CollectResult, Item, Option, PathBuf, Vec, Item, Option (+37 more)

### Community 2 - "Uninstall Execution"
Cohesion: 0.10
Nodes (44): AsRef, Drop, Duration, OsStr, Result, String, Drop, ExecOptions (+36 more)

### Community 3 - "Safety Transactions"
Cohesion: 0.11
Nodes (45): CleanReport, Item, Leftover, Option, Path, PathBuf, RegPath, Result (+37 more)

### Community 4 - "Tauri Commands"
Cohesion: 0.16
Nodes (45): Engine, ExecOptions, FnMut, FnOnce, Option, PathBuf, Request, Result (+37 more)

### Community 5 - "Svelte UI Components"
Cohesion: 0.06
Nodes (34): @tauri-apps/api/app, dependencies, @tauri-apps/api, devDependencies, svelte, svelte-check, @sveltejs/vite-plugin-svelte, @tauri-apps/cli (+26 more)

### Community 6 - "Package Managers & Modules"
Cohesion: 0.11
Nodes (35): Collector, CollectResult, Item, Option, PathBuf, String, Vec, Collector (+27 more)

### Community 7 - "Leftover Scanner"
Cohesion: 0.13
Nodes (23): HashMap, Item, Leftover, Option, Path, PathBuf, RegKey, RegPath (+15 more)

### Community 8 - "Collector Registry & Tasks"
Cohesion: 0.08
Nodes (31): Box, BSTR, Collector, CollectResult, Duration, Item, ItemKind, Option (+23 more)

### Community 9 - "Core Item Model"
Cohesion: 0.10
Nodes (24): Option, Result, Self, Signature, String, Vec, Display, E (+16 more)

### Community 10 - "Registry Programs Collector"
Cohesion: 0.10
Nodes (23): Arch, Collector, CollectResult, Item, Option, RegKey, RegPath, Scope (+15 more)

### Community 11 - "Elevated Broker IPC"
Cohesion: 0.13
Nodes (23): BufRead, BufReader, Drop, FnMut, Option, Request, Result, ScanEvent (+15 more)

### Community 12 - "Engine Request Handler"
Cohesion: 0.16
Nodes (19): ExecOptions, ExecOutcome, FnMut, HashMap, Item, Option, Request, Result (+11 more)

### Community 13 - "Tauri Configuration"
Cohesion: 0.07
Nodes (28): app, security, windows, build, beforeBuildCommand, beforeDevCommand, devUrl, frontendDist (+20 more)

### Community 14 - "Registry I/O & Backup"
Cohesion: 0.16
Nodes (26): Command, AsRef, OsStr, Path, RegKey, RegPath, Result, String (+18 more)

### Community 15 - "DISM Features & Updates"
Cohesion: 0.13
Nodes (15): Arch, Collector, CollectResult, Item, Option, String, Vec, arch_from() (+7 more)

### Community 16 - "SDK & Runtime Detection"
Cohesion: 0.20
Nodes (23): Collector, CollectResult, Item, ItemKind, Option, Path, PathBuf, Scope (+15 more)

### Community 17 - "Driver Packages"
Cohesion: 0.18
Nodes (14): Collector, CollectResult, HashMap, Item, Option, Self, String, Vec (+6 more)

### Community 18 - "Engine Protocol"
Cohesion: 0.18
Nodes (19): Item, Option, String, Vec, CleanReport, CollectorInfo, ExecOptions, ExecOutcome (+11 more)

### Community 19 - "Services Collector"
Cohesion: 0.16
Nodes (13): Collector, CollectResult, Drop, Item, Option, String, Vec, ENUM_SERVICE_STATUS_PROCESSW (+5 more)

### Community 20 - "Startup Entries"
Cohesion: 0.18
Nodes (13): Collector, CollectResult, Item, Option, RegKey, Scope, String, Vec (+5 more)

### Community 21 - "Process Collector"
Cohesion: 0.15
Nodes (12): Collector, CollectResult, Drop, Item, Option, String, Vec, PROCESSENTRY32W (+4 more)

### Community 22 - "Versioning Script"
Cohesion: 0.21
Nodes (15): bump(), [command, arg], commitsSince(), compare(), current(), detectBump(), file(), git() (+7 more)

### Community 23 - "Deny-list"
Cohesion: 0.29
Nodes (13): Option, String, Vec, denied_exact(), denied_trees(), env_dir(), is_denied_key(), is_denied_path() (+5 more)

### Community 24 - "Risk Heuristics"
Cohesion: 0.31
Nodes (13): ItemKind, Option, String, Vec, assess(), flags_encoded_powershell_and_double_extensions(), flags_unsigned_masquerading_autostart(), is_autostart() (+5 more)

### Community 25 - "Path Utilities"
Cohesion: 0.26
Nodes (9): Option, String, exe_from_command(), expand(), is_under(), is_windows_path(), normalize(), parent_dir() (+1 more)

### Community 26 - "AppX Packages"
Cohesion: 0.20
Nodes (8): Collector, CollectResult, Item, Result, Vec, Package, AppxCollector, read_package()

### Community 27 - "Security Features (Docs)"
Cohesion: 0.26
Nodes (12): Leftover Confidence Scoring (0-100), Untrusted Software Heuristics (implementation status), Authenticode Verification (offline, embedded + catalogs), Deep Uninstall, Scan with Microsoft Defender, Risk Score (Untrusted & suspicious >= 40), Snipe (README), snipe-cli (headless CLI) (+4 more)

### Community 28 - "PR Change Detection"
Cohesion: 0.17
Nodes (10): affected, changed, everything, flags, GLOBAL, mergeBase, meta, names (+2 more)

### Community 29 - "TypeScript Config"
Cohesion: 0.18
Nodes (10): compilerOptions, module, moduleResolution, noEmit, skipLibCheck, strict, target, types (+2 more)

### Community 30 - "Date Helpers"
Cohesion: 0.38
Nodes (7): Option, String, civil_from_days(), format_ymd(), from_filetime_ticks(), from_unix_secs(), from_yyyymmdd()

### Community 31 - "Inventory Cache"
Cohesion: 0.36
Nodes (9): Item, Option, PathBuf, Result, Vec, Cached, load(), path() (+1 more)

### Community 32 - "CSV/JSON Export"
Cohesion: 0.42
Nodes (7): Item, String, T, csv_field(), enum_text(), to_csv(), to_json()

### Community 33 - "Secure Data Store"
Cohesion: 0.42
Nodes (8): Option, PathBuf, Result, String, create_secure_dir(), data_root(), owner_sid(), txn_root()

### Community 34 - "Inventory Design (Docs)"
Cohesion: 0.25
Nodes (9): Avoid WMI Win32_Product (use MsiEnumProductsEx), Collector Trait, Incremental Refresh via Collector Fingerprints, Inventory Cache (SQLite planned, JSON snapshot implemented), Inventory Engine, Item Unified Data Model, Preflight (protection + dependency check), Protection Levels (Removable/Shared/SystemCritical/Locked) (+1 more)

### Community 35 - "Frontend & PR CI (Docs)"
Cohesion: 0.25
Nodes (8): app/index.html, /src/main.ts entry module, Testing Strategy (unit, fixture, Windows Sandbox E2E, benchmarks), UninstallString Parsing (CommandLineToArgvW, no cmd /c), Svelte 5 Frontend (app/), .github/scripts/affected.mjs (change detection), CI Result Aggregate Job, Pull Request CI Workflow

### Community 36 - "CLI Entry Point"
Cohesion: 0.36
Nodes (7): Engine, Result, main(), String, ExitCode, run(), scan()

### Community 37 - "Safety Layer (Docs)"
Cohesion: 0.29
Nodes (8): Delete-on-Reboot for Locked Files, File Quarantine, Registry .reg Backup, Never Follow Reparse Points, Safety Layer, Transaction Journal and Undo, Quarantine, .reg Backups and Undo History, Remove Threat

### Community 38 - "Uninstall Pipeline (Docs)"
Cohesion: 0.32
Nodes (8): Forced Removal, Install Tracing via ETW, Job Object for Uninstallers, Leftover (Trace) Scanner, Restart Manager Process Shutdown, System Restore Point (SRSetRestorePoint), Silent Uninstall Switches (Inno /VERYSILENT, NSIS /S, MSI /qn), Uninstall Pipeline

### Community 39 - "Architecture & Tech Choice"
Cohesion: 0.29
Nodes (7): Snipe Architecture & Implementation Plan, Implementation Phases 0-6, Process & Privilege Model (one binary, two modes), Rust + Tauri 2 Technology Choice, Slint Alternative UI, Least Privilege / On-demand Elevated Broker, Tauri 2 (WebView2)

### Community 40 - "Release & Versioning (Docs)"
Cohesion: 0.33
Nodes (7): Conventional Commits, NSIS Installer (x64/x86), Semantic Versioning, scripts/version.mjs, Installer Build Matrix (x86_64 / i686 MSVC), Release Workflow, SHA256SUMS Checksums

### Community 41 - "Tauri Capabilities"
Cohesion: 0.33
Nodes (5): description, identifier, permissions, $schema, windows

### Community 42 - "Broker Security Model"
Cohesion: 0.40
Nodes (5): Elevated Broker Named Pipe (DACL to user SID), Deny-list of Critical Paths and Keys, Item-ID-only Broker Requests, Security Requirements, Deny-list (Windows paths and registry keys)

## Knowledge Gaps
- **234 isolated node(s):** `mergeBase`, `changed`, `GLOBAL`, `everything`, `meta` (+229 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `system32()` connect `Safety Transactions` to `Caches & Signature Trust`, `Uninstall Execution`, `Leftover Scanner`, `Registry I/O & Backup`, `DISM Features & Updates`?**
  _High betweenness centrality (0.112) - this node is a cross-community bridge._
- **Why does `run_dism()` connect `DISM Features & Updates` to `Core Item Model`, `Safety Transactions`, `Registry I/O & Backup`?**
  _High betweenness centrality (0.070) - this node is a cross-community bridge._
- **Why does `Command` connect `Registry I/O & Backup` to `Caches & Signature Trust`, `Tauri Commands`?**
  _High betweenness centrality (0.058) - this node is a cross-community bridge._
- **Are the 4 inferred relationships involving `find()` (e.g. with `dir_size()` and `loaded_user_sids()`) actually correct?**
  _`find()` has 4 INFERRED edges - model-reasoned connections that need verification._
- **Are the 16 inferred relationships involving `env_path()` (e.g. with `candidates()` and `.collect()`) actually correct?**
  _`env_path()` has 16 INFERRED edges - model-reasoned connections that need verification._
- **What connects `mergeBase`, `changed`, `GLOBAL` to the rest of the system?**
  _236 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Frontend API & Types` be split into smaller, more focused modules?**
  _Cohesion score 0.05021173623714459 - nodes in this community are weakly interconnected._