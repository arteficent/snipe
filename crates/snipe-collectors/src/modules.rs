//! PowerShell modules found on every `PSModulePath` root.

use crate::util::{current_user, env_path, read_text};
use snipe_core::{CollectResult, Collector, Item, ItemKind, Protection, Scope, UninstallMethod, paths};
use std::path::{Path, PathBuf};

pub struct ModulesCollector;

/// Modules that ship with Windows PowerShell under Program Files.
const INBOX: &[&str] = &["packagemanagement", "powershellget", "pester", "psreadline", "microsoft.powershell.operation.validation"];

fn roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = std::env::var("PSModulePath")
        .unwrap_or_default()
        .split(';')
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .collect();
    if let Some(docs) = env_path("USERPROFILE").map(|h| h.join("Documents")) {
        roots.push(docs.join(r"PowerShell\Modules"));
        roots.push(docs.join(r"WindowsPowerShell\Modules"));
    }
    if let Some(pf) = env_path("ProgramFiles") {
        roots.push(pf.join(r"PowerShell\Modules"));
        roots.push(pf.join(r"WindowsPowerShell\Modules"));
    }
    roots.push(Path::new(paths::windows_dir()).join(r"System32\WindowsPowerShell\v1.0\Modules"));
    let mut seen = std::collections::HashSet::new();
    roots.retain(|r| r.is_dir() && seen.insert(r.to_string_lossy().to_ascii_lowercase()));
    roots
}

fn psd1_field(text: &str, key: &str) -> Option<String> {
    let line = text.lines().find(|l| {
        let t = l.trim_start();
        t.get(..key.len()).is_some_and(|h| h.eq_ignore_ascii_case(key)) && t[key.len()..].trim_start().starts_with('=')
    })?;
    let value = line.split_once('=')?.1.trim();
    let quote = value.chars().next().filter(|c| *c == '\'' || *c == '"')?;
    let inner = &value[1..];
    Some(inner[..inner.find(quote)?].to_string()).filter(|s| !s.is_empty())
}

fn looks_like_version(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit() || c == '.') && s.contains('.')
}

impl Collector for ModulesCollector {
    fn id(&self) -> &'static str {
        "modules"
    }

    fn label(&self) -> &'static str {
        "PowerShell modules"
    }

    fn collect(&self) -> CollectResult<Vec<Item>> {
        let profile = env_path("USERPROFILE").map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        let mut items = Vec::new();
        for root in roots() {
            let root_str = root.to_string_lossy().into_owned();
            let in_windows = paths::is_windows_path(&root_str);
            let user_scope = !profile.is_empty() && paths::is_under(&root_str, &profile);
            let Ok(entries) = std::fs::read_dir(&root) else { continue };
            for entry in entries.flatten() {
                if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                let dir = entry.path();
                let versions: Vec<PathBuf> = std::fs::read_dir(&dir)
                    .map(|rd| {
                        rd.flatten()
                            .filter(|e| looks_like_version(&e.file_name().to_string_lossy()))
                            .map(|e| e.path())
                            .collect()
                    })
                    .unwrap_or_default();
                let targets = if versions.is_empty() { vec![dir.clone()] } else { versions };
                for target in targets {
                    let manifest = read_text(&target.join(format!("{name}.psd1")));
                    let path = target.to_string_lossy().into_owned();
                    let mut item = Item::new(ItemKind::Module, name.clone(), path.clone());
                    item.install_location = Some(path.clone());
                    item.version = manifest.as_deref().and_then(|m| psd1_field(m, "ModuleVersion")).or_else(|| {
                        let leaf = target.file_name()?.to_string_lossy().into_owned();
                        looks_like_version(&leaf).then_some(leaf)
                    });
                    item.publisher = manifest
                        .as_deref()
                        .and_then(|m| psd1_field(m, "CompanyName").or_else(|| psd1_field(m, "Author")));
                    item.manager = Some("PowerShell".into());
                    if user_scope {
                        item.scope = Scope::User;
                        item.user = current_user();
                    }
                    if in_windows {
                        item.protection = Protection::Locked;
                        item.hidden = true;
                    } else if INBOX.contains(&name.to_ascii_lowercase().as_str()) && !user_scope {
                        item.protection = Protection::System;
                    } else {
                        item.uninstall.push(UninstallMethod::DeletePath { path });
                    }
                    item.detail("Module root", root_str.clone());
                    items.push(item);
                }
            }
        }
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn reads_psd1_fields() {
        let text = "@{\n  RootModule = 'X.psm1'\n  ModuleVersion = '2.1.0'\n  CompanyName = \"Contoso\"\n}";
        assert_eq!(super::psd1_field(text, "ModuleVersion").as_deref(), Some("2.1.0"));
        assert_eq!(super::psd1_field(text, "CompanyName").as_deref(), Some("Contoso"));
        assert_eq!(super::psd1_field(text, "Author"), None);
    }
}
