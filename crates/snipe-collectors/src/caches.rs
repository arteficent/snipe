//! Developer and temp caches, with their on-disk size.

use crate::util::{current_user, dir_size, env_path};
use snipe_core::{CollectResult, Collector, Item, ItemKind, Scope, UninstallMethod};
use std::path::PathBuf;

pub struct CachesCollector;

fn candidates() -> Vec<(&'static str, Option<PathBuf>)> {
    let home = env_path("USERPROFILE");
    let local = env_path("LOCALAPPDATA");
    let h = |p: &str| home.as_ref().map(|h| h.join(p));
    let l = |p: &str| local.as_ref().map(|l| l.join(p));
    vec![
        ("NuGet packages", env_path("NUGET_PACKAGES").or_else(|| h(r".nuget\packages"))),
        ("npm cache", l("npm-cache")),
        ("pip cache", l(r"pip\Cache")),
        ("Yarn cache", l(r"Yarn\Cache")),
        ("pnpm store", l(r"pnpm\store")),
        ("Maven repository", h(r".m2\repository")),
        ("Gradle caches", h(r".gradle\caches")),
        ("Cargo registry", h(r".cargo\registry")),
        ("Go module cache", h(r"go\pkg\mod")),
        ("Crash dumps", l("CrashDumps")),
        ("User temp folder", env_path("TEMP")),
    ]
}

impl Collector for CachesCollector {
    fn id(&self) -> &'static str {
        "caches"
    }

    fn label(&self) -> &'static str {
        "Caches"
    }

    fn collect(&self) -> CollectResult<Vec<Item>> {
        let found: Vec<(&str, PathBuf)> = candidates()
            .into_iter()
            .filter_map(|(label, p)| p.filter(|p| p.is_dir()).map(|p| (label, p)))
            .collect();
        let sizes: Vec<u64> = std::thread::scope(|s| {
            let handles: Vec<_> = found.iter().map(|(_, p)| s.spawn(move || dir_size(p))).collect();
            handles.into_iter().map(|h| h.join().unwrap_or(0)).collect()
        });
        Ok(found
            .into_iter()
            .zip(sizes)
            .map(|((label, path), size)| {
                let path = path.to_string_lossy().into_owned();
                let mut item = Item::new(ItemKind::Cache, label, path.clone());
                item.install_location = Some(path.clone());
                item.size_bytes = Some(size);
                item.scope = Scope::User;
                item.user = current_user();
                item.detail("Note", "Cleaning empties the folder permanently; tools re-download as needed.");
                item.uninstall.push(UninstallMethod::CleanDir { path });
                item
            })
            .collect())
    }
}
