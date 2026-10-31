//! MSIX / AppX packages for the current user via the WinRT PackageManager.

use snipe_core::{Arch, CollectResult, Collector, Item, ItemKind, Protection, Scope, Signature, SignatureStatus, UninstallMethod, date};
use windows::ApplicationModel::{Package, PackageSignatureKind};
use windows::Management::Deployment::PackageManager;
use windows::System::ProcessorArchitecture;
use windows::core::HSTRING;

pub struct AppxCollector;

impl Collector for AppxCollector {
    fn id(&self) -> &'static str {
        "appx"
    }

    fn label(&self) -> &'static str {
        "Store & MSIX apps"
    }

    fn collect(&self) -> CollectResult<Vec<Item>> {
        let manager = PackageManager::new()?;
        // Empty SID = current user; enumerating all users would require elevation.
        let packages = manager.FindPackagesByUserSecurityId(&HSTRING::new())?;
        let mut items = Vec::new();
        for pkg in packages {
            if let Ok(item) = read_package(&pkg) {
                items.push(item);
            }
        }
        Ok(items)
    }
}

fn read_package(pkg: &Package) -> windows::core::Result<Item> {
    let id = pkg.Id()?;
    let full_name = id.FullName()?.to_string();
    let short_name = id.Name()?.to_string();
    let display = pkg
        .DisplayName()
        .map(|s| s.to_string())
        .ok()
        .filter(|s| !s.is_empty() && !s.starts_with("ms-resource:"))
        .unwrap_or_else(|| short_name.clone());

    let mut item = Item::new(ItemKind::Appx, display, full_name.clone());
    item.scope = Scope::User;
    item.user = crate::util::current_user();
    let v = id.Version()?;
    item.version = Some(format!("{}.{}.{}.{}", v.Major, v.Minor, v.Build, v.Revision));
    item.publisher = pkg
        .PublisherDisplayName()
        .map(|s| s.to_string())
        .ok()
        .filter(|s| !s.is_empty() && !s.starts_with("ms-resource:"));
    item.install_location = pkg.InstalledPath().ok().map(|s| s.to_string()).filter(|s| !s.is_empty());
    item.install_date = pkg
        .InstalledDate()
        .ok()
        .and_then(|d| date::from_filetime_ticks(d.UniversalTime));
    item.arch = match id.Architecture()? {
        ProcessorArchitecture::X64 => Arch::X64,
        ProcessorArchitecture::X86 => Arch::X86,
        ProcessorArchitecture::Arm64 => Arch::Arm64,
        ProcessorArchitecture::Neutral => Arch::Neutral,
        _ => Arch::Unknown,
    };

    let is_framework = pkg.IsFramework().unwrap_or(false);
    let is_resource = pkg.IsResourcePackage().unwrap_or(false);
    item.hidden = is_framework || is_resource;
    if pkg.SignatureKind().ok() == Some(PackageSignatureKind::System) {
        item.protection = Protection::System;
    } else if is_framework {
        item.protection = Protection::Shared;
    }

    item.uninstall.push(UninstallMethod::Appx { package_full_name: full_name.clone() });
    item.detail("Package full name", full_name);
    item.detail("Package family", id.FamilyName().map(|s| s.to_string()).unwrap_or_default());
    if is_framework {
        item.detail("Framework", "yes");
    }
    if let Ok(kind) = pkg.SignatureKind() {
        // Sideloaded packages must chain to a machine-trusted certificate to install; only
        // loose-file (developer mode) registrations skip that check.
        let dev_mode = pkg.IsDevelopmentMode().unwrap_or(false);
        let (label, status) = match kind {
            _ if dev_mode => ("Development mode (unsigned registration)", SignatureStatus::Unsigned),
            PackageSignatureKind::Developer => ("Sideloaded", SignatureStatus::Trusted),
            PackageSignatureKind::Enterprise => ("Enterprise", SignatureStatus::Trusted),
            PackageSignatureKind::Store => ("Store", SignatureStatus::Trusted),
            PackageSignatureKind::System => ("System", SignatureStatus::Trusted),
            _ => ("None", SignatureStatus::Unsigned),
        };
        item.detail("Package signature", label);
        item.signature = Some(Signature { status, signer: item.publisher.clone() });
    }
    Ok(item)
}
