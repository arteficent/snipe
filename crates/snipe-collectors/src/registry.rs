//! Classic Win32 / MSI programs from the Uninstall registry keys (machine and every loaded user hive).

use crate::util::{account_from_sid, loaded_user_sids, reg_str, reg_u32};
use snipe_core::cmdline::{is_guid, msi_product_from_command};
use snipe_core::{
    Arch, CollectResult, Collector, Item, ItemKind, Protection, RegPath, Scope, UninstallMethod, date,
    is_shared_runtime, paths,
};
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};

const UNINSTALL_PATH: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

pub struct RegistryCollector;

struct View {
    root: RegKey,
    /// Display/registry prefix, e.g. `HKLM` or `HKU\S-1-5-21-…`.
    prefix: String,
    flags: u32,
    wow32: bool,
    scope: Scope,
    arch: Arch,
    user: Option<String>,
}

impl Collector for RegistryCollector {
    fn id(&self) -> &'static str {
        "registry"
    }

    fn label(&self) -> &'static str {
        "Installed programs"
    }

    fn collect(&self) -> CollectResult<Vec<Item>> {
        let mut views = vec![
            View {
                root: RegKey::predef(HKEY_LOCAL_MACHINE),
                prefix: "HKLM".into(),
                flags: KEY_WOW64_64KEY,
                wow32: false,
                scope: Scope::Machine,
                arch: Arch::X64,
                user: None,
            },
            View {
                root: RegKey::predef(HKEY_LOCAL_MACHINE),
                prefix: "HKLM".into(),
                flags: KEY_WOW64_32KEY,
                wow32: true,
                scope: Scope::Machine,
                arch: Arch::X86,
                user: None,
            },
        ];
        for sid in loaded_user_sids() {
            views.push(View {
                root: RegKey::predef(HKEY_USERS),
                prefix: format!(r"HKU\{sid}"),
                flags: 0,
                wow32: false,
                scope: Scope::User,
                arch: Arch::Unknown,
                user: account_from_sid(&sid),
            });
        }

        let mut items = Vec::new();
        for view in &views {
            let rel = match view.prefix.split_once('\\') {
                Some((_, sid)) => format!(r"{sid}\{UNINSTALL_PATH}"),
                None => UNINSTALL_PATH.to_string(),
            };
            let Ok(root) = view.root.open_subkey_with_flags(&rel, KEY_READ | view.flags) else {
                continue;
            };
            for sub in root.enum_keys().flatten() {
                let Ok(key) = root.open_subkey_with_flags(&sub, KEY_READ | view.flags) else {
                    continue;
                };
                let reg = RegPath::new(format!(r"{}\{UNINSTALL_PATH}\{sub}", view.prefix), view.wow32);
                if let Some(item) = read_entry(&key, &sub, reg, view) {
                    items.push(item);
                }
            }
        }
        Ok(items)
    }
}

fn read_entry(key: &RegKey, sub: &str, reg: RegPath, view: &View) -> Option<Item> {
    let name = reg_str(key, "DisplayName")?;
    let uninstall_string = reg_str(key, "UninstallString");
    let product_code = if reg_u32(key, "WindowsInstaller") == Some(1) && is_guid(sub) {
        Some(sub.to_ascii_uppercase())
    } else {
        uninstall_string.as_deref().and_then(msi_product_from_command)
    };
    let kind = if product_code.is_some() { ItemKind::Msi } else { ItemKind::Win32 };

    let mut item = Item::new(kind, name, reg.to_string());
    item.scope = view.scope;
    item.arch = view.arch;
    item.user = view.user.clone();
    item.version = reg_str(key, "DisplayVersion");
    item.publisher = reg_str(key, "Publisher");
    item.install_location = reg_str(key, "InstallLocation").map(|p| paths::expand(&p));
    item.install_date = reg_str(key, "InstallDate").and_then(|d| date::from_yyyymmdd(&d));
    item.size_bytes = reg_u32(key, "EstimatedSize").map(|kb| kb as u64 * 1024);

    let system_component = reg_u32(key, "SystemComponent") == Some(1);
    let is_update = reg_str(key, "ParentKeyName").is_some()
        || reg_str(key, "ReleaseType").is_some_and(|t| {
            let t = t.to_ascii_lowercase();
            t.contains("update") || t.contains("hotfix")
        });
    item.hidden = system_component || is_update;

    if is_shared_runtime(&item.name) {
        item.protection = Protection::Shared;
    }

    if let Some(code) = &product_code {
        item.uninstall.push(UninstallMethod::Msi { product_code: code.clone() });
    }
    if let Some(cmd) = reg_str(key, "QuietUninstallString") {
        item.uninstall.push(UninstallMethod::Command { command: cmd, quiet: true });
    }
    if let Some(cmd) = uninstall_string {
        item.detail("Uninstall command", cmd.clone());
        if product_code.is_none() {
            item.uninstall.push(UninstallMethod::Command { command: cmd, quiet: false });
        }
    }

    if item.install_location.is_none() {
        item.install_location = reg_str(key, "DisplayIcon")
            .and_then(|icon| paths::exe_from_command(icon.split(',').next().unwrap_or_default()))
            .and_then(|exe| paths::parent_dir(&exe))
            .filter(|dir| !paths::is_windows_path(dir));
    }

    item.executable = reg_str(key, "DisplayIcon")
        .and_then(|icon| paths::exe_from_command(icon.split(',').next().unwrap_or_default()))
        .filter(|exe| exe.to_ascii_lowercase().ends_with(".exe") && std::path::Path::new(exe).is_file())
        .or_else(|| {
            item.uninstall.iter().find_map(|m| match m {
                UninstallMethod::Command { command, .. } => paths::exe_from_command(command)
                    .filter(|e| !e.to_ascii_lowercase().ends_with("msiexec.exe") && std::path::Path::new(e).is_file()),
                _ => None,
            })
        });

    item.detail("Registry key", reg.to_string());
    if let Some(v) = reg_str(key, "URLInfoAbout") {
        item.detail("Website", v);
    }
    if let Some(v) = reg_str(key, "Comments") {
        item.detail("Comments", v);
    }
    if system_component {
        item.detail("System component", "yes");
    }
    if is_update {
        item.detail("Update of", reg_str(key, "ParentDisplayName").unwrap_or_default());
    }
    item.registry = Some(reg);
    Some(item)
}
