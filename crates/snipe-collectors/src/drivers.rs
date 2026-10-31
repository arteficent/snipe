//! Third-party driver packages (`%WINDIR%\INF\oem*.inf`).

use crate::util::read_text;
use snipe_core::{CollectResult, Collector, Item, ItemKind, Protection, UninstallMethod, paths};
use std::collections::HashMap;
use std::path::Path;

pub struct DriversCollector;

impl Collector for DriversCollector {
    fn id(&self) -> &'static str {
        "drivers"
    }

    fn label(&self) -> &'static str {
        "Drivers"
    }

    fn collect(&self) -> CollectResult<Vec<Item>> {
        let dir = Path::new(paths::windows_dir()).join("INF");
        let mut items = Vec::new();
        for entry in std::fs::read_dir(&dir)?.flatten() {
            let file = entry.file_name().to_string_lossy().into_owned();
            let lower = file.to_ascii_lowercase();
            if !(lower.starts_with("oem") && lower.ends_with(".inf")) {
                continue;
            }
            let Some(text) = read_text(&entry.path()) else { continue };
            items.push(to_item(&file, &entry.path().to_string_lossy(), &Inf::parse(&text)));
        }
        Ok(items)
    }
}

#[derive(Default)]
struct Inf {
    version: HashMap<String, String>,
    strings: HashMap<String, String>,
    string_order: Vec<String>,
}

impl Inf {
    fn parse(text: &str) -> Self {
        let mut inf = Inf::default();
        let mut section = String::new();
        for raw in text.lines() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].trim().to_ascii_lowercase();
                continue;
            }
            let Some((k, v)) = line.split_once('=') else { continue };
            let key = k.trim().to_ascii_lowercase();
            let value = v.trim().trim_matches('"').to_string();
            match section.as_str() {
                "version" => {
                    inf.version.insert(key, value);
                }
                "strings" => {
                    if !inf.strings.contains_key(&key) {
                        inf.string_order.push(key.clone());
                    }
                    inf.strings.insert(key, value);
                }
                _ => {}
            }
        }
        inf
    }

    fn resolve(&self, value: &str) -> String {
        let v = value.trim();
        if let Some(token) = v.strip_prefix('%').and_then(|s| s.strip_suffix('%')) {
            return self.strings.get(&token.to_ascii_lowercase()).cloned().unwrap_or_else(|| v.to_string());
        }
        v.to_string()
    }

    fn get(&self, key: &str) -> Option<String> {
        self.version.get(key).map(|v| self.resolve(v)).filter(|v| !v.is_empty())
    }

    fn description(&self) -> Option<String> {
        self.string_order
            .iter()
            .find(|k| k.contains("desc") || k.contains("devicename") || k.ends_with("name"))
            .and_then(|k| self.strings.get(k))
            .cloned()
            .filter(|v| !v.is_empty())
    }
}

fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ';' if !in_quotes => return &line[..i],
            _ => {}
        }
    }
    line
}

fn to_item(file: &str, full_path: &str, inf: &Inf) -> Item {
    let provider = inf.get("provider");
    let class = inf.get("class").unwrap_or_else(|| "Device".into());
    let name = inf
        .description()
        .unwrap_or_else(|| format!("{} {class} driver", provider.as_deref().unwrap_or("Unknown")));

    let mut item = Item::new(ItemKind::Driver, format!("{name} ({file})"), full_path.to_string());
    item.publisher = provider;
    item.protection = Protection::Shared;
    if let Some(driver_ver) = inf.get("driverver") {
        let (date, version) = driver_ver.split_once(',').unwrap_or((&driver_ver, ""));
        item.version = Some(version.trim().to_string()).filter(|v| !v.is_empty());
        item.install_date = parse_mdy(date.trim());
    }
    item.detail("INF", file.to_string());
    item.detail("Class", class);
    item.detail("Class GUID", inf.get("classguid").unwrap_or_default());
    item.detail("Catalog", inf.get("catalogfile").unwrap_or_default());
    item.uninstall.push(UninstallMethod::Driver { inf: file.to_string() });
    item
}

/// INF dates are `mm/dd/yyyy`.
fn parse_mdy(s: &str) -> Option<String> {
    let mut parts = s.split('/');
    let m: u32 = parts.next()?.trim().parse().ok()?;
    let d: u32 = parts.next()?.trim().parse().ok()?;
    let y: u32 = parts.next()?.trim().parse().ok()?;
    ((1..=12).contains(&m) && (1..=31).contains(&d)).then(|| format!("{y:04}-{m:02}-{d:02}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_inf() {
        let text = "[Version]\r\nSignature=\"$WINDOWS NT$\"\r\nClass=Net ; comment\r\nProvider=%Mfg%\r\nDriverVer=06/21/2023,1.2.3.4\r\n[Strings]\r\nMfg=\"Contoso; Ltd\"\r\nDeviceDesc=\"Contoso NIC\"\r\n";
        let inf = Inf::parse(text);
        let item = to_item("oem12.inf", r"C:\Windows\INF\oem12.inf", &inf);
        assert_eq!(item.publisher.as_deref(), Some("Contoso; Ltd"));
        assert_eq!(item.version.as_deref(), Some("1.2.3.4"));
        assert_eq!(item.install_date.as_deref(), Some("2023-06-21"));
        assert_eq!(item.name, "Contoso NIC (oem12.inf)");
    }
}
