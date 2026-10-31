//! Autostart entries: Run/RunOnce registry keys and Startup folders (machine and every user).

use crate::util::{account_from_sid, loaded_user_sids, profiles};
use snipe_core::{CollectResult, Collector, Item, ItemKind, Protection, RegPath, Scope, UninstallMethod, paths};
use std::path::Path;
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};

const RUN: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
const RUN_ONCE: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
const APPROVED: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";
const STARTUP_DIR: &str = r"Microsoft\Windows\Start Menu\Programs\Startup";
const EXECUTABLE_TYPES: &[&str] = &[".exe", ".com", ".scr", ".pif", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".dll"];

pub struct StartupCollector;

struct Hive {
    root: RegKey,
    /// Path of the hive below `root` ("" for HKLM, the SID for HKU).
    base: String,
    prefix: String,
    scope: Scope,
    user: Option<String>,
}

impl Hive {
    fn rel(&self, path: &str) -> String {
        if self.base.is_empty() { path.to_string() } else { format!(r"{}\{path}", self.base) }
    }
}

impl Collector for StartupCollector {
    fn id(&self) -> &'static str {
        "startup"
    }

    fn label(&self) -> &'static str {
        "Startup entries"
    }

    fn collect(&self) -> CollectResult<Vec<Item>> {
        let mut hives = vec![Hive {
            root: RegKey::predef(HKEY_LOCAL_MACHINE),
            base: String::new(),
            prefix: "HKLM".into(),
            scope: Scope::Machine,
            user: None,
        }];
        for sid in loaded_user_sids() {
            hives.push(Hive {
                root: RegKey::predef(HKEY_USERS),
                prefix: format!(r"HKU\{sid}"),
                user: account_from_sid(&sid),
                base: sid,
                scope: Scope::User,
            });
        }

        let mut items = Vec::new();
        for hive in &hives {
            let is_machine = hive.scope == Scope::Machine;
            let views: &[(u32, bool, &str)] = if is_machine {
                &[(KEY_WOW64_64KEY, false, "Run"), (KEY_WOW64_32KEY, true, "Run32")]
            } else {
                &[(0, false, "Run")]
            };
            for &(view, wow32, approved_sub) in views {
                for (path, once) in [(RUN, false), (RUN_ONCE, true)] {
                    let Ok(key) = hive.root.open_subkey_with_flags(hive.rel(path), KEY_READ | view) else {
                        continue;
                    };
                    for (name, _) in key.enum_values().flatten() {
                        let Ok(command) = key.get_value::<String, _>(&name) else { continue };
                        let reg = RegPath::new(format!(r"{}\{path}", hive.prefix), wow32);
                        let mut item = Item::new(ItemKind::Startup, display_name(&name), format!(r"{reg}\{name}"));
                        item.scope = hive.scope;
                        item.user = hive.user.clone();
                        let enabled = once || is_enabled(hive, approved_sub, &name);
                        fill(&mut item, &command, enabled, &format!(r"{reg}\{name}"));
                        item.uninstall.push(UninstallMethod::RegistryValue { key: reg, value: name });
                        items.push(item);
                    }
                }
            }
        }

        let mut folders = Vec::new();
        if let Ok(pd) = std::env::var("ProgramData") {
            folders.push((Path::new(&pd).join(STARTUP_DIR), Scope::Machine, None, None));
        }
        for (sid, profile) in profiles() {
            let dir = profile.join(r"AppData\Roaming").join(STARTUP_DIR);
            folders.push((dir, Scope::User, account_from_sid(&sid), Some(sid)));
        }
        for (dir, scope, user, sid) in folders {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            let hive = match &sid {
                Some(sid) => hives.iter().find(|h| &h.base == sid),
                None => hives.first(),
            };
            for entry in entries.flatten() {
                let file_name = entry.file_name().to_string_lossy().into_owned();
                if file_name.eq_ignore_ascii_case("desktop.ini") {
                    continue;
                }
                let full = entry.path().to_string_lossy().into_owned();
                let mut item = Item::new(ItemKind::Startup, display_name(&file_name), full.clone());
                item.scope = scope;
                item.user = user.clone();
                let enabled = hive.is_none_or(|h| is_enabled(h, "StartupFolder", &file_name));
                fill(&mut item, &full, enabled, &full);
                item.uninstall.push(UninstallMethod::DeletePath { path: full });
                items.push(item);
            }
        }
        Ok(items)
    }
}

fn display_name(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    for ext in [".lnk", ".url", ".exe", ".bat", ".cmd"] {
        if lower.ends_with(ext) {
            return raw[..raw.len() - ext.len()].to_string();
        }
    }
    raw.to_string()
}

fn fill(item: &mut Item, command: &str, enabled: bool, location: &str) {
    item.detail("Command", command.to_string());
    item.detail("Enabled", if enabled { "yes" } else { "no" });
    item.detail("Location", location.to_string());
    if let Some(exe) = paths::exe_from_command(command) {
        let lower = exe.to_ascii_lowercase();
        if EXECUTABLE_TYPES.iter().any(|e| lower.ends_with(e)) {
            item.executable = Some(exe.clone());
        }
        if paths::is_windows_path(&exe) {
            item.protection = Protection::System;
        } else {
            item.install_location = paths::parent_dir(&exe);
        }
    }
}

/// `StartupApproved` stores a binary blob per entry; an odd first byte means disabled.
fn is_enabled(hive: &Hive, sub: &str, name: &str) -> bool {
    hive.root
        .open_subkey_with_flags(hive.rel(&format!(r"{APPROVED}\{sub}")), KEY_READ)
        .and_then(|k| k.get_raw_value(name))
        .map(|v| v.bytes.first().is_none_or(|b| b & 1 == 0))
        .unwrap_or(true)
}
