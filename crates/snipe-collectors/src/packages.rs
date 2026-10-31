//! Packages installed through package managers: Chocolatey, Scoop, npm, pip, cargo and dotnet tools.

use crate::util::{current_user, env_path, read_text};
use snipe_core::{CollectResult, Collector, Item, ItemKind, Scope, UninstallMethod};
use std::path::{Path, PathBuf};

pub struct PackageManagersCollector;

impl Collector for PackageManagersCollector {
    fn id(&self) -> &'static str {
        "packages"
    }

    fn label(&self) -> &'static str {
        "Package managers"
    }

    fn collect(&self) -> CollectResult<Vec<Item>> {
        let mut items = Vec::new();
        chocolatey(&mut items);
        scoop(&mut items);
        npm(&mut items);
        pip(&mut items);
        cargo(&mut items);
        dotnet_tools(&mut items);
        Ok(items)
    }
}

fn home() -> Option<PathBuf> {
    env_path("USERPROFILE")
}

fn package(manager: &str, name: &str, version: Option<String>, location: &Path, scope: Scope) -> Item {
    let loc = location.to_string_lossy().into_owned();
    let mut item = Item::new(ItemKind::Package, name, format!("{manager}:{loc}"));
    item.manager = Some(manager.to_string());
    item.version = version;
    item.install_location = Some(loc);
    item.scope = scope;
    if scope == Scope::User {
        item.user = current_user();
    }
    item.detail("Package manager", manager.to_string());
    item
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

fn xml_tag(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&format!("</{tag}>"))? + start;
    Some(text[start..end].trim().to_string()).filter(|s| !s.is_empty())
}

fn chocolatey(items: &mut Vec<Item>) {
    let root = env_path("ChocolateyInstall")
        .or_else(|| env_path("ProgramData").map(|p| p.join("chocolatey")));
    let Some(root) = root else { return };
    for (name, dir) in subdirs(&root.join("lib")) {
        let Some(nuspec) = read_text(&dir.join(format!("{name}.nuspec"))) else { continue };
        let id = xml_tag(&nuspec, "id").unwrap_or(name.clone());
        let mut item = package("choco", &id, xml_tag(&nuspec, "version"), &dir, Scope::Machine);
        if let Some(title) = xml_tag(&nuspec, "title") {
            item.name = title;
        }
        item.publisher = xml_tag(&nuspec, "authors");
        item.detail("Package id", id.clone());
        item.detail("Summary", xml_tag(&nuspec, "summary").unwrap_or_default());
        item.uninstall.push(UninstallMethod::PackageManager { manager: "choco".into(), name: id, tool: None });
        items.push(item);
    }
}

fn scoop(items: &mut Vec<Item>) {
    let roots = [
        (env_path("SCOOP").or_else(|| home().map(|h| h.join("scoop"))), Scope::User),
        (env_path("SCOOP_GLOBAL").or_else(|| env_path("ProgramData").map(|p| p.join("scoop"))), Scope::Machine),
    ];
    for (root, scope) in roots {
        let Some(root) = root else { continue };
        for (name, dir) in subdirs(&root.join("apps")) {
            let manifest = read_text(&dir.join(r"current\manifest.json"))
                .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok());
            let Some(manifest) = manifest else { continue };
            let version = manifest["version"].as_str().map(str::to_string);
            let mut item = package("scoop", &name, version, &dir, scope);
            item.detail("Description", manifest["description"].as_str().unwrap_or_default());
            item.detail("Homepage", manifest["homepage"].as_str().unwrap_or_default());
            let tool = (scope == Scope::Machine).then(|| "global".to_string());
            item.uninstall.push(UninstallMethod::PackageManager { manager: "scoop".into(), name, tool });
            items.push(item);
        }
    }
}

fn npm(items: &mut Vec<Item>) {
    let Some(root) = env_path("APPDATA").map(|p| p.join(r"npm\node_modules")) else { return };
    let mut dirs = Vec::new();
    for (name, dir) in subdirs(&root) {
        if name.starts_with('@') {
            dirs.extend(subdirs(&dir));
        } else if !name.starts_with('.') {
            dirs.push((name, dir));
        }
    }
    for (_, dir) in dirs {
        let Some(json) = read_text(&dir.join("package.json"))
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        else {
            continue;
        };
        let Some(name) = json["name"].as_str().map(str::to_string) else { continue };
        let mut item = package("npm", &name, json["version"].as_str().map(str::to_string), &dir, Scope::User);
        item.publisher = json["author"]
            .as_str()
            .map(str::to_string)
            .or_else(|| json["author"]["name"].as_str().map(str::to_string));
        item.detail("Description", json["description"].as_str().unwrap_or_default());
        item.uninstall.push(UninstallMethod::PackageManager { manager: "npm".into(), name, tool: None });
        items.push(item);
    }
}

struct DistInfo {
    name: String,
    version: Option<String>,
    summary: Option<String>,
    author: Option<String>,
}

fn read_metadata(dist_info: &Path) -> Option<DistInfo> {
    let text = read_text(&dist_info.join("METADATA"))?;
    let field = |key: &str| {
        text.lines()
            .take_while(|l| !l.is_empty())
            .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
            .filter(|v| !v.is_empty() && v != "UNKNOWN")
    };
    Some(DistInfo {
        name: field("Name:")?,
        version: field("Version:"),
        summary: field("Summary:"),
        author: field("Author:"),
    })
}

fn pip(items: &mut Vec<Item>) {
    let pf = env_path("ProgramFiles").map(|p| p.to_string_lossy().to_ascii_lowercase());
    for install in crate::sdks::python_installs() {
        let python = install.path.join("python.exe");
        if !python.is_file() {
            continue;
        }
        let machine = pf.as_ref().is_some_and(|pf| install.path.to_string_lossy().to_ascii_lowercase().starts_with(pf));
        let mut site_dirs = vec![install.path.join(r"Lib\site-packages")];
        if let (Some(appdata), Some(ver)) = (env_path("APPDATA"), &install.version) {
            let short: String = ver.split('.').take(2).collect::<Vec<_>>().join("");
            site_dirs.push(appdata.join(format!(r"Python\Python{short}\site-packages")));
        }
        for (i, site) in site_dirs.iter().enumerate() {
            let scope = if i == 0 && machine { Scope::Machine } else { Scope::User };
            for (dir_name, dir) in subdirs(site) {
                if !dir_name.ends_with(".dist-info") {
                    continue;
                }
                let Some(DistInfo { name, version, summary, author }) = read_metadata(&dir) else { continue };
                let mut item = package("pip", &name, version, &dir, scope);
                item.publisher = author;
                item.detail("Interpreter", python.to_string_lossy());
                item.detail("Summary", summary.unwrap_or_default());
                item.uninstall.push(UninstallMethod::PackageManager {
                    manager: "pip".into(),
                    name,
                    tool: Some(python.to_string_lossy().into_owned()),
                });
                items.push(item);
            }
        }
    }
}

fn cargo(items: &mut Vec<Item>) {
    let Some(root) = env_path("CARGO_HOME").or_else(|| home().map(|h| h.join(".cargo"))) else { return };
    let Some(json) = read_text(&root.join(".crates2.json"))
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
    else {
        return;
    };
    let Some(installs) = json["installs"].as_object() else { return };
    for (key, info) in installs {
        let mut parts = key.split_whitespace();
        let (Some(name), version) = (parts.next(), parts.next()) else { continue };
        let mut item = package("cargo", name, version.map(str::to_string), &root.join("bin"), Scope::User);
        item.source = format!("cargo:{name}");
        item.id = snipe_core::make_id(ItemKind::Package, &item.source);
        let bins: Vec<&str> = info["bins"].as_array().map(|a| a.iter().filter_map(|b| b.as_str()).collect()).unwrap_or_default();
        item.detail("Binaries", bins.join(", "));
        item.detail("Source", key.clone());
        item.uninstall.push(UninstallMethod::PackageManager { manager: "cargo".into(), name: name.into(), tool: None });
        items.push(item);
    }
}

fn dotnet_tools(items: &mut Vec<Item>) {
    let Some(store) = home().map(|h| h.join(r".dotnet\tools\.store")) else { return };
    for (id, dir) in subdirs(&store) {
        if id.starts_with('.') {
            continue;
        }
        let version = subdirs(&dir).into_iter().map(|(v, _)| v).next();
        let mut item = package("dotnet-tool", &id, version, &dir, Scope::User);
        item.uninstall.push(UninstallMethod::PackageManager { manager: "dotnet-tool".into(), name: id, tool: None });
        items.push(item);
    }
}
