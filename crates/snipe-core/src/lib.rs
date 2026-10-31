//! Shared data model, collector trait and helpers used across Snipe.

pub mod cmdline;
pub mod date;
pub mod deny;
pub mod paths;
pub mod risk;

pub use risk::{Signature, SignatureStatus};

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum ItemKind {
    Win32,
    Msi,
    Appx,
    Feature,
    Capability,
    Update,
    Driver,
    Service,
    Process,
    Task,
    Startup,
    Package,
    Module,
    Sdk,
    Runtime,
    Cache,
}

impl ItemKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ItemKind::Win32 => "win32",
            ItemKind::Msi => "msi",
            ItemKind::Appx => "appx",
            ItemKind::Feature => "feature",
            ItemKind::Capability => "capability",
            ItemKind::Update => "update",
            ItemKind::Driver => "driver",
            ItemKind::Service => "service",
            ItemKind::Process => "process",
            ItemKind::Task => "task",
            ItemKind::Startup => "startup",
            ItemKind::Package => "package",
            ItemKind::Module => "module",
            ItemKind::Sdk => "sdk",
            ItemKind::Runtime => "runtime",
            ItemKind::Cache => "cache",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Scope {
    Machine,
    User,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Arch {
    X64,
    X86,
    Arm64,
    Neutral,
    Unknown,
}

/// How dangerous it is to remove an item.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum Protection {
    Removable,
    /// Runtime or library other software may depend on.
    Shared,
    /// Ships with Windows; removable only through supported mechanisms.
    System,
    /// Never touched by Snipe.
    Locked,
}

/// A registry key, e.g. `HKLM\SOFTWARE\Foo` or `HKU\S-1-5-21-…\Software\Foo`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct RegPath {
    pub key: String,
    /// Use the 32-bit (WOW6432Node) view.
    pub wow32: bool,
}

impl RegPath {
    pub fn new(key: impl Into<String>, wow32: bool) -> Self {
        Self { key: key.into(), wow32 }
    }
}

impl fmt::Display for RegPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.key)?;
        if self.wow32 {
            f.write_str(" (32-bit)")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum UninstallMethod {
    Command { command: String, quiet: bool },
    Msi { product_code: String },
    Appx { package_full_name: String },
    Service { name: String },
    Driver { inf: String },
    Feature { name: String },
    Capability { name: String },
    Update { package: String },
    Task { path: String },
    RegistryValue { key: RegPath, value: String },
    PackageManager { manager: String, name: String, tool: Option<String> },
    DeletePath { path: String },
    /// Empties a folder but keeps it (caches).
    CleanDir { path: String },
}

impl UninstallMethod {
    pub fn label(&self) -> String {
        match self {
            Self::Command { command, quiet } => {
                format!("{} {command}", if *quiet { "Quiet uninstaller:" } else { "Uninstaller:" })
            }
            Self::Msi { product_code } => format!("Windows Installer: msiexec /x {product_code}"),
            Self::Appx { package_full_name } => format!("Remove package {package_full_name}"),
            Self::Service { name } => format!("Stop and delete service {name}"),
            Self::Driver { inf } => format!("Remove driver package {inf}"),
            Self::Feature { name } => format!("Disable Windows feature {name}"),
            Self::Capability { name } => format!("Remove capability {name}"),
            Self::Update { package } => format!("Remove package {package}"),
            Self::Task { path } => format!("Delete scheduled task {path}"),
            Self::RegistryValue { key, value } => format!("Delete registry value {key}\\{value}"),
            Self::PackageManager { manager, name, .. } => format!("{manager} uninstall {name}"),
            Self::DeletePath { path } => format!("Delete {path}"),
            Self::CleanDir { path } => format!("Empty {path}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub id: String,
    pub kind: ItemKind,
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_location: Option<String>,
    pub install_date: Option<String>,
    pub size_bytes: Option<u64>,
    pub scope: Scope,
    /// Account the item belongs to or runs as.
    pub user: Option<String>,
    pub arch: Arch,
    pub protection: Protection,
    /// Flagged by Windows as a system component, framework, update or similar.
    pub hidden: bool,
    /// Package manager that owns the item (npm, pip, choco…).
    pub manager: Option<String>,
    pub uninstall: Vec<UninstallMethod>,
    /// Registry key that registers the item, if any.
    pub registry: Option<RegPath>,
    /// Main executable (or service DLL) used for signature and risk checks.
    pub executable: Option<String>,
    pub signature: Option<Signature>,
    /// Heuristic 0–100 risk score; see [`risk::assess`].
    pub risk: u8,
    pub risk_reasons: Vec<String>,
    /// Where the item was discovered (registry key, path, service name...).
    pub source: String,
    pub details: Vec<(String, String)>,
}

impl Item {
    pub fn new(kind: ItemKind, name: impl Into<String>, source: impl Into<String>) -> Self {
        let source = source.into();
        Self {
            id: make_id(kind, &source),
            kind,
            name: name.into(),
            version: None,
            publisher: None,
            install_location: None,
            install_date: None,
            size_bytes: None,
            scope: Scope::Machine,
            user: None,
            arch: Arch::Unknown,
            protection: Protection::Removable,
            hidden: false,
            manager: None,
            uninstall: Vec::new(),
            registry: None,
            executable: None,
            signature: None,
            risk: 0,
            risk_reasons: Vec::new(),
            source,
            details: Vec::new(),
        }
    }

    pub fn detail(&mut self, label: &str, value: impl Into<String>) {
        let value = value.into();
        if !value.is_empty() {
            self.details.push((label.to_string(), value));
        }
    }

    /// Why this item may not be removed, if it is blocked.
    pub fn removal_block(&self) -> Option<&'static str> {
        if self.uninstall.is_empty() {
            return Some("No removal method is known for this item.");
        }
        match self.protection {
            Protection::Locked => Some("This item is critical to Windows and is never removed."),
            Protection::System
                if !matches!(self.kind, ItemKind::Feature | ItemKind::Capability | ItemKind::Update) =>
            {
                Some("This is a Windows component; Snipe only removes it through supported mechanisms.")
            }
            _ => None,
        }
    }
}

/// Stable FNV-1a hash of kind + case-insensitive source.
pub fn make_id(kind: ItemKind, source: &str) -> String {
    let bytes = kind
        .as_str()
        .bytes()
        .chain(std::iter::once(0u8))
        .chain(source.bytes().map(|b| b.to_ascii_lowercase()));
    format!("{:016x}", fnv1a(bytes))
}

pub fn fnv1a(bytes: impl IntoIterator<Item = u8>) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Heuristic for runtimes and redistributables that other software depends on.
pub fn is_shared_runtime(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    (n.contains("visual c++") && (n.contains("redistributable") || n.contains("runtime")))
        || n.starts_with("microsoft .net")
        || n.starts_with("microsoft asp.net core")
        || n.starts_with("microsoft windows desktop runtime")
        || n.contains("webview2 runtime")
        || n.contains("directx")
        || n.contains("vcredist")
}

/// Error type for collectors. Any `std::error::Error` converts into it, so `?` just works.
#[derive(Debug)]
pub struct CollectError(pub String);

impl fmt::Display for CollectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<E: std::error::Error> From<E> for CollectError {
    fn from(e: E) -> Self {
        CollectError(e.to_string())
    }
}

pub type CollectResult<T> = Result<T, CollectError>;

pub trait Collector: Send + Sync {
    fn id(&self) -> &'static str;
    fn label(&self) -> &'static str;
    fn requires_admin(&self) -> bool {
        false
    }
    fn collect(&self) -> CollectResult<Vec<Item>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_stable_and_case_insensitive() {
        let a = make_id(ItemKind::Win32, r"HKLM\Software\Foo");
        let b = make_id(ItemKind::Win32, r"hklm\software\foo");
        assert_eq!(a, b);
        assert_ne!(a, make_id(ItemKind::Msi, r"HKLM\Software\Foo"));
    }

    #[test]
    fn shared_runtime_detection() {
        assert!(is_shared_runtime("Microsoft Visual C++ 2015-2022 Redistributable (x64)"));
        assert!(is_shared_runtime("Microsoft .NET Runtime - 8.0.8 (x64)"));
        assert!(!is_shared_runtime("7-Zip 24.08 (x64)"));
    }

    #[test]
    fn removal_blocking() {
        let mut item = Item::new(ItemKind::Win32, "App", "x");
        assert!(item.removal_block().is_some());
        item.uninstall.push(UninstallMethod::DeletePath { path: r"C:\x".into() });
        assert!(item.removal_block().is_none());
        item.protection = Protection::Locked;
        assert!(item.removal_block().is_some());
        item.kind = ItemKind::Feature;
        item.protection = Protection::System;
        assert!(item.removal_block().is_none());
    }
}
