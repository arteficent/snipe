//! Inventory cache for instant warm starts (`%LOCALAPPDATA%\Snipe\inventory.json`).

use serde::{Deserialize, Serialize};
use snipe_core::Item;
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
pub struct Cached {
    pub saved: u64,
    pub items: Vec<Item>,
}

fn path() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|p| PathBuf::from(p).join("Snipe").join("inventory.json"))
}

pub fn load() -> Option<Cached> {
    let text = std::fs::read(path()?).ok()?;
    serde_json::from_slice(&text).ok()
}

pub fn save(items: &[Item]) -> std::io::Result<()> {
    let path = path().ok_or_else(|| std::io::Error::other("LOCALAPPDATA not set"))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let saved = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(&Cached { saved, items: items.to_vec() })?)?;
    std::fs::rename(tmp, path)
}
