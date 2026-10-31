//! Leftover ("trace") scanner: finds files, folders, registry data, services, tasks and PATH
//! entries an item left behind, and scores how confident we are that each belongs to it.

use crate::protocol::{Leftover, Target};
use crate::regio;
use snipe_collectors::util::{dir_size, loaded_user_sids, profiles, read_text, system32};
use snipe_core::{Item, ItemKind, RegPath, UninstallMethod, deny, paths};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};

pub const PRESELECT: u8 = 80;
const MIN_SCORE: u8 = 40;

/// Words too generic to identify a product on their own.
const GENERIC: &[&str] = &[
    "app", "apps", "bin", "data", "program", "programs", "software", "common", "commonfiles", "update",
    "updater", "setup", "install", "installer", "tools", "temp", "cache", "logs", "microsoft", "windows",
    "system", "user", "users", "config", "settings", "shared", "local", "roaming", "default", "x64", "x86",
];

pub fn normalize(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric()).flat_map(char::to_lowercase).collect()
}

/// Product name without versions, architecture tags and parenthesised suffixes.
fn clean_name(name: &str) -> String {
    let mut out = String::new();
    let mut depth = 0;
    for c in name.chars() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth = (depth - 1).max(0),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace()
        .filter(|w| {
            let lw = w.to_ascii_lowercase();
            let versionish = w.chars().any(|c| c.is_ascii_digit()) && w.chars().all(|c| c.is_ascii_digit() || ".-_v".contains(c));
            !versionish && !["x64", "x86", "64-bit", "32-bit", "arm64", "-", "–"].contains(&lw.as_str())
        })
        .collect::<Vec<_>>()
        .join(" ")
}

struct Matcher {
    keys: Vec<String>,
    publisher: Option<String>,
    install_dir: Option<String>,
}

impl Matcher {
    fn new(item: &Item) -> Self {
        let mut keys = Vec::new();
        let cleaned = clean_name(&item.name);
        keys.push(normalize(&cleaned));
        let publisher = item.publisher.as_deref().map(|p| {
            let first = p.split([' ', ',', '.']).next().unwrap_or(p);
            normalize(first)
        });
        if let Some(pub_key) = &publisher {
            let n = normalize(&cleaned);
            if let Some(rest) = n.strip_prefix(pub_key.as_str()) {
                keys.push(rest.to_string());
            }
        }
        let install_dir = item
            .install_location
            .as_deref()
            .map(|p| p.trim().trim_end_matches('\\').to_string())
            .filter(|p| !p.is_empty() && !deny::is_denied_path(p) && Path::new(p).is_absolute());
        if let Some(dir) = &install_dir
            && let Some(leaf) = Path::new(dir).file_name()
        {
            keys.push(normalize(&clean_name(&leaf.to_string_lossy())));
        }
        if item.kind == ItemKind::Appx
            && let Some((_, family)) = item.details.iter().find(|(k, _)| k == "Package family")
        {
            keys.push(normalize(family));
        }
        keys.retain(|k| k.len() >= 3 && !GENERIC.contains(&k.as_str()));
        keys.sort();
        keys.dedup();
        Self { keys, publisher: publisher.filter(|p| p.len() >= 3 && !GENERIC.contains(&p.as_str())), install_dir }
    }

    /// Name score for a folder/key name: exact product match or fuzzy similarity.
    fn name_score(&self, name: &str) -> Option<(u8, &'static str)> {
        let n = normalize(&clean_name(name));
        if n.len() < 3 {
            return None;
        }
        if self.keys.contains(&n) {
            return Some((75, "name matches the product"));
        }
        let best = self
            .keys
            .iter()
            .filter(|k| k.len() >= 5)
            .map(|k| strsim::jaro_winkler(k, &n))
            .fold(0.0, f64::max);
        (best >= 0.92).then_some((45, "name is similar to the product"))
    }

    fn is_publisher(&self, name: &str) -> bool {
        self.publisher.as_deref().is_some_and(|p| {
            let n = normalize(name);
            n == p || (p.len() >= 5 && n.starts_with(p))
        })
    }

    fn mentions_install_dir(&self, text: &str) -> bool {
        self.install_dir.as_deref().is_some_and(|d| {
            let t = text.to_ascii_lowercase();
            let d = d.to_ascii_lowercase();
            t.match_indices(&d).any(|(i, _)| {
                // Must be the folder itself or something inside it, not a sibling with a longer name.
                matches!(t.as_bytes().get(i + d.len()), None | Some(b'\\') | Some(b'"') | Some(b';') | Some(b'\0'))
            })
        })
    }
}

struct Finder<'a> {
    matcher: Matcher,
    item: &'a Item,
    /// Install folders of every other product; anything overlapping them is excluded.
    others: Vec<String>,
    found: HashMap<String, Leftover>,
}

impl Finder<'_> {
    fn add(&mut self, target: Target, score: u8, reason: &str) {
        let score = score.min(100);
        let id = target.id();
        if let Some(existing) = self.found.get_mut(&id) {
            existing.score = existing.score.max(score);
            if !existing.reasons.iter().any(|r| r == reason) {
                existing.reasons.push(reason.to_string());
            }
            existing.preselected = existing.score >= PRESELECT;
            return;
        }
        if score < MIN_SCORE {
            return;
        }
        self.found.insert(
            id.clone(),
            Leftover {
                id,
                display: target.display(),
                target,
                score,
                reasons: vec![reason.to_string()],
                size_bytes: None,
                preselected: score >= PRESELECT,
            },
        );
    }

    fn overlaps_other_product(&self, path: &str) -> bool {
        self.others.iter().any(|o| paths::is_under(path, o) || paths::is_under(o, path))
    }

    fn add_path(&mut self, path: &Path, score: u8, reason: &str) {
        let s = path.to_string_lossy().into_owned();
        if deny::is_denied_path(&s) || self.overlaps_other_product(&s) {
            return;
        }
        let Ok(meta) = std::fs::symlink_metadata(path) else { return };
        let target = if meta.is_dir() { Target::Dir { path: s } } else { Target::File { path: s } };
        self.add(target, score, reason);
    }

    /// Looks for product-named children, and product folders inside a publisher folder.
    fn scan_folder(&mut self, root: &Path) {
        let Ok(entries) = std::fs::read_dir(root) else { return };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
            let stem = name.rsplit_once('.').filter(|_| !is_dir).map(|(s, _)| s.to_string()).unwrap_or(name.clone());
            if let Some((score, reason)) = self.matcher.name_score(&stem) {
                self.add_path(&entry.path(), score + 5, reason);
            } else if is_dir && self.matcher.is_publisher(&name) {
                let Ok(children) = std::fs::read_dir(entry.path()) else { continue };
                for child in children.flatten() {
                    let cname = child.file_name().to_string_lossy().into_owned();
                    if let Some((score, reason)) = self.matcher.name_score(&cname) {
                        self.add_path(&child.path(), score + 15, reason);
                    }
                }
            }
        }
    }

    fn scan_shortcuts(&mut self, root: &Path, depth: u32) {
        let Ok(entries) = std::fs::read_dir(root) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_dir {
                if let Some((score, reason)) = self.matcher.name_score(&name) {
                    self.add_path(&path, score + 10, reason);
                } else if depth > 0 {
                    self.scan_shortcuts(&path, depth - 1);
                }
                continue;
            }
            if !name.to_ascii_lowercase().ends_with(".lnk") {
                continue;
            }
            if self.matcher.install_dir.is_some() && lnk_mentions(&path, self.matcher.install_dir.as_deref().unwrap_or("")) {
                self.add_path(&path, 90, "shortcut points into the install folder");
            } else if let Some((score, reason)) = self.matcher.name_score(&name[..name.len() - 4]) {
                self.add_path(&path, score, reason);
            }
        }
    }

    fn scan_registry_names(&mut self, root: &RegKey, prefix: &str, wow32: bool, flags: u32) {
        let Ok(software) = root.open_subkey_with_flags("", KEY_READ | flags) else { return };
        for name in software.enum_keys().flatten() {
            let key = RegPath::new(format!(r"{prefix}\{name}"), wow32);
            if let Some((score, reason)) = self.matcher.name_score(&name) {
                if !deny::is_denied_key(&key.key) {
                    self.add(Target::RegKey { key }, score + 5, reason);
                }
            } else if self.matcher.is_publisher(&name) {
                let Ok(vendor) = software.open_subkey_with_flags(&name, KEY_READ | flags) else { continue };
                for product in vendor.enum_keys().flatten() {
                    if let Some((score, reason)) = self.matcher.name_score(&product) {
                        let key = RegPath::new(format!(r"{prefix}\{name}\{product}"), wow32);
                        if !deny::is_denied_key(&key.key) {
                            self.add(Target::RegKey { key }, score + 15, reason);
                        }
                    }
                }
            }
        }
    }

    /// Values whose data (or name) points into the install folder.
    fn scan_values(&mut self, key: &RegPath, check_names: bool, score: u8, reason: &str) {
        let Ok(k) = regio::open(key, false) else { return };
        for (name, value) in k.enum_values().flatten() {
            let data = value.to_string();
            let hit = self.matcher.mentions_install_dir(&data)
                || (check_names && self.matcher.mentions_install_dir(&name));
            if hit && !deny::is_denied_value(&key.key) {
                self.add(Target::RegValue { key: key.clone(), name }, score, reason);
            }
        }
    }

    /// Subkeys whose default value / `Path` / server points into the install folder.
    fn scan_subkeys(&mut self, key: &RegPath, server_sub: &[&str], score: u8, reason: &str) {
        let Ok(k) = regio::open(key, false) else { return };
        for name in k.enum_keys().flatten() {
            let Ok(sub) = k.open_subkey_with_flags(&name, KEY_READ) else { continue };
            let mut hit = false;
            if server_sub.is_empty() {
                for v in ["", "Path"] {
                    hit |= sub.get_value::<String, _>(v).is_ok_and(|d| self.matcher.mentions_install_dir(&d));
                }
            } else {
                for s in server_sub {
                    hit |= sub
                        .open_subkey_with_flags(s, KEY_READ)
                        .and_then(|srv| srv.get_value::<String, _>(""))
                        .is_ok_and(|d| self.matcher.mentions_install_dir(&d));
                }
            }
            if hit {
                let target_key = RegPath::new(format!(r"{}\{name}", key.key), key.wow32);
                if !deny::is_denied_key(&target_key.key) {
                    self.add(Target::RegKey { key: target_key }, score, reason);
                }
            }
        }
    }

    fn scan_services(&mut self) {
        let Ok(services) = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Services", KEY_READ)
        else {
            return;
        };
        for name in services.enum_keys().flatten() {
            let Ok(k) = services.open_subkey_with_flags(&name, KEY_READ) else { continue };
            let Ok(image) = k.get_value::<String, _>("ImagePath") else { continue };
            if self.matcher.mentions_install_dir(&paths::expand(&image)) {
                self.add(Target::Service { name }, 90, "service runs from the install folder");
            }
        }
    }

    fn scan_tasks(&mut self, dir: &Path, rel: &str) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = format!(r"{rel}\{name}");
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                if !(rel.is_empty() && name.eq_ignore_ascii_case("Microsoft")) {
                    self.scan_tasks(&entry.path(), &path);
                }
            } else if read_text(&entry.path()).is_some_and(|t| self.matcher.mentions_install_dir(&paths::expand(&t))) {
                self.add(Target::Task { path }, 85, "scheduled task runs from the install folder");
            }
        }
    }

    fn scan_env_path(&mut self, key: RegPath) {
        let Ok(k) = regio::open(&key, false) else { return };
        let Ok(value) = k.get_value::<String, _>("Path") else { return };
        for entry in value.split(';').filter(|e| !e.trim().is_empty()) {
            if self.matcher.mentions_install_dir(&paths::expand(entry)) {
                self.add(Target::EnvPath { key: key.clone(), entry: entry.to_string() }, 90, "PATH entry points into the install folder");
            }
        }
    }
}

/// True if a `.lnk` file references `dir` (checked in both UTF-16 and ANSI forms).
fn lnk_mentions(path: &Path, dir: &str) -> bool {
    let Ok(bytes) = std::fs::read(path) else { return false };
    if bytes.len() > 1 << 20 || dir.is_empty() {
        return false;
    }
    let lower: Vec<u8> = bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
    let d = dir.to_ascii_lowercase();
    let ansi = d.as_bytes();
    let wide: Vec<u8> = d.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    lower.windows(ansi.len()).any(|w| w == ansi) || lower.windows(wide.len()).any(|w| w == wide.as_slice())
}

/// Windows Installer "packed" GUID used under `Installer\Products`.
pub fn packed_guid(guid: &str) -> Option<String> {
    let g: String = guid.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if g.len() != 32 {
        return None;
    }
    let rev = |s: &str| s.chars().rev().collect::<String>();
    let mut out = rev(&g[0..8]) + &rev(&g[8..12]) + &rev(&g[12..16]);
    for i in (16..32).step_by(2) {
        out.push_str(&rev(&g[i..i + 2]));
    }
    Some(out.to_ascii_uppercase())
}

fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(PathBuf::from)
}

/// Finds leftovers for `item`. `inventory` is used to protect folders owned by other products.
pub fn find(item: &Item, inventory: &[Item]) -> Vec<Leftover> {
    let matcher = Matcher::new(item);
    let others = inventory
        .iter()
        .filter(|o| o.id != item.id)
        .filter(|o| {
            matches!(
                o.kind,
                ItemKind::Win32 | ItemKind::Msi | ItemKind::Appx | ItemKind::Sdk | ItemKind::Runtime | ItemKind::Package | ItemKind::Module
            )
        })
        .filter_map(|o| o.install_location.clone())
        .filter(|l| Some(l.trim_end_matches('\\')) != matcher.install_dir.as_deref() && !deny::is_denied_path(l))
        .collect();
    let mut f = Finder { matcher, item, others, found: HashMap::new() };

    // The registration itself, if the uninstaller left it behind.
    if let Some(reg) = &f.item.registry
        && regio::exists(reg)
    {
        f.add(Target::RegKey { key: reg.clone() }, 100, "uninstall entry is still registered");
    }

    if let Some(dir) = f.matcher.install_dir.clone()
        && Path::new(&dir).exists()
    {
        f.add_path(Path::new(&dir), 95, "install folder");
    }

    // Folders named after the product.
    let mut roots: Vec<PathBuf> = Vec::new();
    for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramData", "CommonProgramFiles", "CommonProgramFiles(x86)"] {
        roots.extend(env_dir(var));
    }
    let user_profiles = profiles();
    for (_, profile) in &user_profiles {
        for sub in [r"AppData\Roaming", r"AppData\Local", r"AppData\LocalLow", r"AppData\Local\Programs", r"AppData\Local\Temp"] {
            roots.push(profile.join(sub));
        }
    }
    for root in &roots {
        f.scan_folder(root);
    }

    // Shortcuts.
    let mut shortcut_roots: Vec<PathBuf> = Vec::new();
    if let Some(pd) = env_dir("ProgramData") {
        shortcut_roots.push(pd.join(r"Microsoft\Windows\Start Menu\Programs"));
    }
    if let Some(public) = env_dir("PUBLIC") {
        shortcut_roots.push(public.join("Desktop"));
    }
    for (_, profile) in &user_profiles {
        shortcut_roots.push(profile.join(r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs"));
        shortcut_roots.push(profile.join("Desktop"));
    }
    for root in &shortcut_roots {
        f.scan_shortcuts(root, 1);
    }

    // AppX per-user data.
    if f.item.kind == ItemKind::Appx
        && let Some((_, family)) = f.item.details.iter().find(|(k, _)| k == "Package family").cloned()
    {
        for (_, profile) in &user_profiles {
            let dir = profile.join(r"AppData\Local\Packages").join(&family);
            if dir.exists() {
                f.add_path(&dir, 95, "app package data");
            }
        }
    }

    // MSI registration and package cache.
    let product_code = f.item.uninstall.iter().find_map(|m| match m {
        UninstallMethod::Msi { product_code } => Some(product_code.clone()),
        _ => None,
    });
    if let Some(code) = &product_code {
        if let Some(packed) = packed_guid(code) {
            for key in [
                format!(r"HKLM\SOFTWARE\Classes\Installer\Products\{packed}"),
                format!(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\{packed}"),
            ] {
                let reg = RegPath::new(key, false);
                if regio::exists(&reg) {
                    f.add(Target::RegKey { key: reg }, 90, "Windows Installer registration");
                }
            }
        }
        if let Some(cache) = env_dir("ProgramData").map(|p| p.join("Package Cache"))
            && let Ok(entries) = std::fs::read_dir(cache)
        {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().to_ascii_uppercase().starts_with(code.as_str()) {
                    f.add_path(&entry.path(), 90, "installer package cache");
                }
            }
        }
    }

    // Registry keys named after the product.
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    for (flags, wow32) in [(KEY_WOW64_64KEY, false), (KEY_WOW64_32KEY, true)] {
        if let Ok(sw) = hklm.open_subkey_with_flags("SOFTWARE", KEY_READ | flags) {
            f.scan_registry_names(&sw, r"HKLM\SOFTWARE", wow32, flags);
        }
    }
    let sids = loaded_user_sids();
    for sid in &sids {
        if let Ok(sw) = RegKey::predef(HKEY_USERS).open_subkey_with_flags(format!(r"{sid}\Software"), KEY_READ) {
            f.scan_registry_names(&sw, &format!(r"HKU\{sid}\Software"), false, 0);
        }
    }

    // References to the install folder.
    if f.matcher.install_dir.is_some() {
        let cv = r"SOFTWARE\Microsoft\Windows\CurrentVersion";
        for wow32 in [false, true] {
            for sub in ["Run", "RunOnce"] {
                f.scan_values(&RegPath::new(format!(r"HKLM\{cv}\{sub}"), wow32), false, 85, "starts from the install folder");
            }
            f.scan_values(&RegPath::new(format!(r"HKLM\{cv}\SharedDLLs"), wow32), true, 70, "shared DLL reference");
            f.scan_subkeys(&RegPath::new(format!(r"HKLM\{cv}\App Paths"), wow32), &[], 90, "App Paths entry");
            f.scan_subkeys(
                &RegPath::new(r"HKLM\SOFTWARE\Classes\CLSID", wow32),
                &["InprocServer32", "LocalServer32"],
                80,
                "COM class served from the install folder",
            );
        }
        f.scan_values(
            &RegPath::new(r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules", false),
            false,
            80,
            "firewall rule for the app",
        );
        f.scan_env_path(RegPath::new(r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment", false));
        for sid in &sids {
            let base = format!(r"HKU\{sid}");
            for sub in ["Run", "RunOnce"] {
                f.scan_values(&RegPath::new(format!(r"{base}\Software\Microsoft\Windows\CurrentVersion\{sub}"), false), false, 85, "starts from the install folder");
            }
            f.scan_subkeys(&RegPath::new(format!(r"{base}\Software\Microsoft\Windows\CurrentVersion\App Paths"), false), &[], 90, "App Paths entry");
            f.scan_subkeys(
                &RegPath::new(format!(r"HKU\{sid}_Classes\CLSID"), false),
                &["InprocServer32", "LocalServer32"],
                80,
                "COM class served from the install folder",
            );
            f.scan_values(
                &RegPath::new(format!(r"HKU\{sid}_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"), false),
                true,
                60,
                "Explorer name cache",
            );
            f.scan_env_path(RegPath::new(format!(r"{base}\Environment"), false));
        }
        f.scan_services();
        f.scan_tasks(&system32("Tasks"), "");
    }

    let mut out: Vec<Leftover> = f.found.into_values().collect();
    for l in &mut out {
        if let Target::Dir { path } = &l.target {
            l.size_bytes = Some(dir_size(Path::new(path)));
        } else if let Target::File { path } = &l.target {
            l.size_bytes = std::fs::metadata(path).ok().map(|m| m.len());
        }
    }
    out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.display.cmp(&b.display)));
    out
}

/// Targets removed directly by a "recorded removal" method (startup entries, tasks, services, folders).
pub fn method_target(method: &UninstallMethod) -> Option<Target> {
    match method {
        UninstallMethod::Service { name } => Some(Target::Service { name: name.clone() }),
        UninstallMethod::Task { path } => Some(Target::Task { path: path.clone() }),
        UninstallMethod::RegistryValue { key, value } => Some(Target::RegValue { key: key.clone(), name: value.clone() }),
        UninstallMethod::DeletePath { path } => {
            let dir = Path::new(path).is_dir();
            Some(if dir { Target::Dir { path: path.clone() } } else { Target::File { path: path.clone() } })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_product_names() {
        assert_eq!(normalize(&clean_name("7-Zip 24.08 (x64)")), "7zip");
        assert_eq!(normalize(&clean_name("Mozilla Firefox (x64 en-US)")), "mozillafirefox");
        assert_eq!(normalize(&clean_name("Notepad++ v8.6")), "notepad");
    }

    #[test]
    fn packs_msi_guids() {
        assert_eq!(packed_guid("{90160000-008C-0000-1000-0000000FF1CE}").as_deref(), Some("00006109C80000000100000000F01FEC"));
    }

    #[test]
    fn matcher_scores() {
        let mut item = Item::new(ItemKind::Win32, "Mozilla Firefox (x64 en-US)", "x");
        item.publisher = Some("Mozilla".into());
        item.install_location = Some(r"C:\Program Files\Mozilla Firefox".into());
        let m = Matcher::new(&item);
        assert_eq!(m.name_score("Mozilla Firefox").map(|s| s.0), Some(75));
        assert_eq!(m.name_score("Firefox").map(|s| s.0), Some(75));
        assert!(m.name_score("Thunderbird").is_none());
        assert!(m.is_publisher("Mozilla"));
        assert!(m.mentions_install_dir(r#""C:\Program Files\Mozilla Firefox\firefox.exe" -osint"#));
        assert!(!m.mentions_install_dir(r"C:\Program Files\Mozilla Firefox Beta\firefox.exe"));
    }
}
