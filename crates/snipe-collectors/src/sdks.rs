//! Developer SDKs and runtimes discovered from well-known locations.

use crate::util::{current_user, env_path, read_text, reg_str};
use snipe_core::{CollectResult, Collector, Item, ItemKind, Protection, Scope, UninstallMethod};
use std::path::{Path, PathBuf};
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};

pub struct SdkCollector;

impl Collector for SdkCollector {
    fn id(&self) -> &'static str {
        "sdks"
    }

    fn label(&self) -> &'static str {
        "SDKs & runtimes"
    }

    fn collect(&self) -> CollectResult<Vec<Item>> {
        let mut items = Vec::new();
        dotnet(&mut items);
        python(&mut items);
        windows_kits(&mut items);
        java(&mut items);
        rustup(&mut items);
        visual_studio(&mut items);
        node_versions(&mut items);
        android(&mut items);
        Ok(items)
    }
}

fn subdirs(dir: &Path) -> Vec<(String, PathBuf)> {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path()))
                .collect()
        })
        .unwrap_or_default()
}

fn path_item(kind: ItemKind, name: String, version: &str, path: &Path, scope: Scope) -> Item {
    let loc = path.to_string_lossy().into_owned();
    let mut item = Item::new(kind, name, loc.clone());
    item.version = Some(version.to_string());
    item.install_location = Some(loc);
    item.scope = scope;
    if scope == Scope::User {
        item.user = current_user();
    }
    item
}

fn dotnet(items: &mut Vec<Item>) {
    let roots = [env_path("ProgramFiles"), env_path("ProgramFiles(x86)")];
    for root in roots.into_iter().flatten() {
        let base = root.join("dotnet");
        for (ver, path) in subdirs(&base.join("sdk")) {
            if ver.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                let mut item = path_item(ItemKind::Sdk, format!(".NET SDK {ver}"), &ver, &path, Scope::Machine);
                item.publisher = Some("Microsoft Corporation".into());
                item.protection = Protection::Shared;
                item.detail("Note", "Remove through the matching \"Microsoft .NET SDK\" program entry.");
                items.push(item);
            }
        }
        for (framework, fpath) in subdirs(&base.join("shared")) {
            for (ver, path) in subdirs(&fpath) {
                let mut item =
                    path_item(ItemKind::Runtime, format!("{framework} {ver}"), &ver, &path, Scope::Machine);
                item.publisher = Some("Microsoft Corporation".into());
                item.protection = Protection::Shared;
                items.push(item);
            }
        }
    }
}

pub(crate) struct PythonInstall {
    pub name: String,
    pub company: String,
    pub version: Option<String>,
    pub path: PathBuf,
    pub scope: Scope,
    pub source: String,
}

/// Python interpreters registered per PEP 514.
pub(crate) fn python_installs() -> Vec<PythonInstall> {
    let views = [
        (HKEY_CURRENT_USER, "HKCU", 0, Scope::User),
        (HKEY_LOCAL_MACHINE, "HKLM", KEY_WOW64_64KEY, Scope::Machine),
        (HKEY_LOCAL_MACHINE, "HKLM32", KEY_WOW64_32KEY, Scope::Machine),
    ];
    let mut out = Vec::new();
    for (hive, hive_name, view, scope) in views {
        let Ok(root) = RegKey::predef(hive).open_subkey_with_flags(r"SOFTWARE\Python", KEY_READ | view) else {
            continue;
        };
        for company in root.enum_keys().flatten() {
            if company.eq_ignore_ascii_case("PyLauncher") {
                continue;
            }
            let Ok(ckey) = root.open_subkey_with_flags(&company, KEY_READ | view) else { continue };
            for tag in ckey.enum_keys().flatten() {
                let Ok(tkey) = ckey.open_subkey_with_flags(&tag, KEY_READ | view) else { continue };
                let Some(path) = tkey
                    .open_subkey_with_flags("InstallPath", KEY_READ | view)
                    .ok()
                    .and_then(|k| reg_str(&k, ""))
                else {
                    continue;
                };
                out.push(PythonInstall {
                    name: reg_str(&tkey, "DisplayName").unwrap_or_else(|| format!("Python {tag}")),
                    company: company.clone(),
                    version: reg_str(&tkey, "Version").or_else(|| reg_str(&tkey, "SysVersion")),
                    path: PathBuf::from(path),
                    scope,
                    source: format!(r"{hive_name}\SOFTWARE\Python\{company}\{tag}"),
                });
            }
        }
    }
    out
}

fn python(items: &mut Vec<Item>) {
    for install in python_installs() {
        let mut item = Item::new(ItemKind::Runtime, install.name, install.source.clone());
        item.version = install.version;
        item.publisher = Some(install.company);
        item.install_location = Some(install.path.to_string_lossy().into_owned());
        item.scope = install.scope;
        if install.scope == Scope::User {
            item.user = current_user();
        }
        item.detail("Registry key", install.source);
        item.detail("Note", "Remove through the matching Python program entry.");
        items.push(item);
    }
}

fn windows_kits(items: &mut Vec<Item>) {
    let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
        r"SOFTWARE\Microsoft\Windows Kits\Installed Roots",
        KEY_READ | KEY_WOW64_32KEY,
    ) else {
        return;
    };
    let root = reg_str(&key, "KitsRoot10");
    for ver in key.enum_keys().flatten() {
        if !ver.starts_with("10.") {
            continue;
        }
        let source = format!(r"HKLM32\SOFTWARE\Microsoft\Windows Kits\Installed Roots\{ver}");
        let mut item = Item::new(ItemKind::Sdk, format!("Windows SDK {ver}"), source);
        item.version = Some(ver);
        item.publisher = Some("Microsoft Corporation".into());
        item.install_location = root.clone();
        item.protection = Protection::Shared;
        items.push(item);
    }
}

fn java(items: &mut Vec<Item>) {
    let products = [
        ("JDK", "Java Development Kit", ItemKind::Sdk),
        ("Java Development Kit", "Java Development Kit", ItemKind::Sdk),
        ("JRE", "Java Runtime Environment", ItemKind::Runtime),
        ("Java Runtime Environment", "Java Runtime Environment", ItemKind::Runtime),
    ];
    for (view, hive_name) in [(KEY_WOW64_64KEY, "HKLM"), (KEY_WOW64_32KEY, "HKLM32")] {
        for (sub, label, kind) in products {
            let path = format!(r"SOFTWARE\JavaSoft\{sub}");
            let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(&path, KEY_READ | view) else {
                continue;
            };
            for ver in key.enum_keys().flatten() {
                let Ok(vkey) = key.open_subkey_with_flags(&ver, KEY_READ | view) else { continue };
                let Some(home) = reg_str(&vkey, "JavaHome") else { continue };
                let mut item = Item::new(kind, format!("{label} {ver}"), format!(r"{hive_name}\{path}\{ver}"));
                item.version = Some(ver);
                item.install_location = Some(home);
                item.protection = Protection::Shared;
                items.push(item);
            }
        }
    }
}

fn rustup(items: &mut Vec<Item>) {
    let home = env_path("RUSTUP_HOME").or_else(|| env_path("USERPROFILE").map(|p| p.join(".rustup")));
    let Some(home) = home else { return };
    for (name, path) in subdirs(&home.join("toolchains")) {
        let version = name.split('-').next().unwrap_or(&name).to_string();
        let mut item = path_item(ItemKind::Sdk, format!("Rust toolchain {name}"), &version, &path, Scope::User);
        item.publisher = Some("Rust Project".into());
        item.manager = Some("rustup".into());
        item.uninstall.push(UninstallMethod::PackageManager { manager: "rustup".into(), name, tool: None });
        items.push(item);
    }
}

fn visual_studio(items: &mut Vec<Item>) {
    let Some(instances) = env_path("ProgramData").map(|p| p.join(r"Microsoft\VisualStudio\Packages\_Instances")) else {
        return;
    };
    let installer = env_path("ProgramFiles(x86)").map(|p| p.join(r"Microsoft Visual Studio\Installer\setup.exe"));
    for (id, dir) in subdirs(&instances) {
        let Some(state) = read_text(&dir.join("state.json"))
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        else {
            continue;
        };
        let Some(path) = state["installationPath"].as_str() else { continue };
        let title = state["localizedResources"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|r| r["title"].as_str())
            .or_else(|| state["installationName"].as_str())
            .unwrap_or("Visual Studio");
        let mut item = Item::new(ItemKind::Sdk, title, format!("vs-instance:{id}"));
        item.version = state["catalogInfo"]["productDisplayVersion"]
            .as_str()
            .or_else(|| state["installationVersion"].as_str())
            .map(str::to_string);
        item.publisher = Some("Microsoft Corporation".into());
        item.install_location = Some(path.to_string());
        item.install_date = state["installDate"].as_str().and_then(|d| d.get(..10)).map(str::to_string);
        item.detail("Instance id", id);
        if let Some(setup) = installer.as_ref().filter(|p| p.is_file()) {
            item.uninstall.push(UninstallMethod::Command {
                command: format!(r#""{}" uninstall --installPath "{path}" --passive --norestart"#, setup.display()),
                quiet: true,
            });
        }
        items.push(item);
    }
}

fn node_versions(items: &mut Vec<Item>) {
    let roots = [
        ("nvm", env_path("NVM_HOME").or_else(|| env_path("APPDATA").map(|p| p.join("nvm")))),
        ("volta", env_path("LOCALAPPDATA").map(|p| p.join(r"Volta\tools\image\node"))),
        ("fnm", env_path("APPDATA").map(|p| p.join(r"fnm\node-versions"))),
    ];
    for (manager, root) in roots {
        let Some(root) = root else { continue };
        for (name, path) in subdirs(&root) {
            let version = name.trim_start_matches('v');
            if !version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                continue;
            }
            let mut item = path_item(ItemKind::Runtime, format!("Node.js {version} ({manager})"), version, &path, Scope::User);
            item.publisher = Some("OpenJS Foundation".into());
            item.manager = Some(manager.into());
            item.uninstall.push(UninstallMethod::DeletePath { path: path.to_string_lossy().into_owned() });
            items.push(item);
        }
    }
}

fn android(items: &mut Vec<Item>) {
    let root = env_path("ANDROID_HOME")
        .or_else(|| env_path("ANDROID_SDK_ROOT"))
        .or_else(|| env_path("LOCALAPPDATA").map(|p| p.join(r"Android\Sdk")));
    let Some(root) = root.filter(|r| r.is_dir()) else { return };
    for (group, label) in [("platforms", "Android platform"), ("build-tools", "Android build-tools"), ("ndk", "Android NDK")] {
        for (name, path) in subdirs(&root.join(group)) {
            let mut item = path_item(ItemKind::Sdk, format!("{label} {name}"), &name, &path, Scope::User);
            item.publisher = Some("Google".into());
            item.uninstall.push(UninstallMethod::DeletePath { path: path.to_string_lossy().into_owned() });
            items.push(item);
        }
    }
}
