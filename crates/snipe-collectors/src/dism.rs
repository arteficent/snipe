//! Windows optional features, capabilities and servicing packages via `dism.exe` (admin only).

use crate::util::{hidden_command, system32};
use snipe_core::{Arch, CollectError, CollectResult, Collector, Item, ItemKind, Protection, UninstallMethod};
use std::sync::Mutex;

/// DISM sessions on the online image are serialized to avoid servicing-lock conflicts.
static DISM_LOCK: Mutex<()> = Mutex::new(());

fn run_dism(command: &str) -> CollectResult<String> {
    let _guard = DISM_LOCK.lock().map_err(|_| CollectError("dism lock poisoned".into()))?;
    let out = hidden_command(system32("dism.exe"))
        .args(["/online", "/english", "/format:table", command])
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        let msg = stdout.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").trim().to_string();
        return Err(CollectError(format!("dism {command} failed ({}): {msg}", out.status.code().unwrap_or(-1))));
    }
    Ok(stdout)
}

/// Rows of a DISM `/format:table` listing.
fn parse_table(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut in_table = false;
    for line in text.lines() {
        let t = line.trim();
        if !in_table {
            in_table = !t.is_empty() && t.contains('-') && t.chars().all(|c| matches!(c, '-' | '|' | ' '));
            continue;
        }
        if t.is_empty() || !t.contains('|') {
            if t.is_empty() && !rows.is_empty() {
                break;
            }
            continue;
        }
        rows.push(t.split('|').map(|c| c.trim().to_string()).collect());
    }
    rows
}

/// DISM dates look like `1/10/2024 5:12 AM`.
fn parse_us_date(s: &str) -> Option<String> {
    let date = s.split_whitespace().next()?;
    let mut parts = date.split('/');
    let m: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    let y: u32 = parts.next()?.parse().ok()?;
    ((1..=12).contains(&m) && (1..=31).contains(&d)).then(|| format!("{y:04}-{m:02}-{d:02}"))
}

fn arch_from(token: &str) -> Arch {
    match token.to_ascii_lowercase().as_str() {
        "amd64" | "x64" => Arch::X64,
        "x86" | "wow64" => Arch::X86,
        "arm64" => Arch::Arm64,
        "" | "neutral" => Arch::Neutral,
        _ => Arch::Unknown,
    }
}

pub struct FeaturesCollector;

impl Collector for FeaturesCollector {
    fn id(&self) -> &'static str {
        "features"
    }
    fn label(&self) -> &'static str {
        "Windows features"
    }
    fn requires_admin(&self) -> bool {
        true
    }
    fn collect(&self) -> CollectResult<Vec<Item>> {
        let text = run_dism("/get-features")?;
        Ok(parse_table(&text)
            .into_iter()
            .filter(|r| r.len() >= 2 && r[1].to_ascii_lowercase().starts_with("enable"))
            .map(|r| {
                let mut item = Item::new(ItemKind::Feature, r[0].clone(), format!("feature:{}", r[0]));
                item.publisher = Some("Microsoft Corporation".into());
                item.protection = Protection::System;
                item.detail("State", r[1].clone());
                item.uninstall.push(UninstallMethod::Feature { name: r[0].clone() });
                item
            })
            .collect())
    }
}

pub struct CapabilitiesCollector;

impl Collector for CapabilitiesCollector {
    fn id(&self) -> &'static str {
        "capabilities"
    }
    fn label(&self) -> &'static str {
        "Windows capabilities"
    }
    fn requires_admin(&self) -> bool {
        true
    }
    fn collect(&self) -> CollectResult<Vec<Item>> {
        let text = run_dism("/get-capabilities")?;
        Ok(parse_table(&text)
            .into_iter()
            .filter(|r| r.len() >= 2 && r[1].eq_ignore_ascii_case("installed"))
            .map(|r| {
                let identity = r[0].clone();
                let parts: Vec<&str> = identity.split('~').collect();
                let mut name = parts[0].to_string();
                if let Some(lang) = parts.get(3).filter(|l| !l.is_empty()) {
                    name = format!("{name} ({lang})");
                }
                let mut item = Item::new(ItemKind::Capability, name, format!("capability:{identity}"));
                item.version = parts.last().filter(|_| parts.len() > 1).map(|v| v.to_string());
                item.publisher = Some("Microsoft Corporation".into());
                item.protection = Protection::System;
                item.detail("Identity", identity.clone());
                item.uninstall.push(UninstallMethod::Capability { name: identity });
                item
            })
            .collect())
    }
}

pub struct PackagesCollector;

impl Collector for PackagesCollector {
    fn id(&self) -> &'static str {
        "updates"
    }
    fn label(&self) -> &'static str {
        "Windows updates & packages"
    }
    fn requires_admin(&self) -> bool {
        true
    }
    fn collect(&self) -> CollectResult<Vec<Item>> {
        let text = run_dism("/get-packages")?;
        Ok(parse_table(&text)
            .into_iter()
            .filter(|r| r.len() >= 2 && r[1].eq_ignore_ascii_case("installed"))
            .map(|r| {
                let identity = r[0].clone();
                let parts: Vec<&str> = identity.split('~').collect();
                let release = r.get(2).cloned().unwrap_or_default();
                let mut item = Item::new(ItemKind::Update, parts[0].to_string(), format!("package:{identity}"));
                item.version = parts.last().filter(|_| parts.len() > 1).map(|v| v.to_string());
                item.arch = parts.get(2).map(|a| arch_from(a)).unwrap_or(Arch::Unknown);
                item.publisher = Some("Microsoft Corporation".into());
                item.install_date = r.get(3).and_then(|d| parse_us_date(d));
                let rl = release.to_ascii_lowercase();
                item.protection = if rl.contains("foundation") { Protection::Locked } else { Protection::System };
                item.hidden = !rl.contains("update") && !rl.contains("hotfix");
                item.detail("Identity", identity.clone());
                item.detail("Release type", release);
                item.uninstall.push(UninstallMethod::Update { package: identity });
                item
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dism_tables() {
        let text = "Deployment Image Servicing and Management tool\r\nVersion: 10.0\r\n\r\nFeature Name | State\r\n------------ | --------\r\nTelnetClient | Disabled\r\nNetFx3       | Enabled\r\n\r\nThe operation completed successfully.\r\n";
        let rows = parse_table(text);
        assert_eq!(rows, vec![vec!["TelnetClient".to_string(), "Disabled".into()], vec!["NetFx3".into(), "Enabled".into()]]);
        assert_eq!(parse_us_date("1/10/2024 5:12 AM").as_deref(), Some("2024-01-10"));
    }
}
