//! Inventory collectors. Each one is independent and read-only.

mod appx;
mod caches;
mod dism;
mod drivers;
mod modules;
mod packages;
mod processes;
mod registry;
mod sdks;
mod services;
mod startup;
mod tasks;
pub mod trust;
pub mod util;

use snipe_core::{CollectError, CollectResult, Collector, Item, ItemKind};
use std::time::{Duration, Instant};

pub fn all() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(registry::RegistryCollector),
        Box::new(appx::AppxCollector),
        Box::new(services::ServicesCollector),
        Box::new(processes::ProcessesCollector),
        Box::new(startup::StartupCollector),
        Box::new(tasks::TasksCollector),
        Box::new(drivers::DriversCollector),
        Box::new(dism::FeaturesCollector),
        Box::new(dism::CapabilitiesCollector),
        Box::new(dism::PackagesCollector),
        Box::new(packages::PackageManagersCollector),
        Box::new(modules::ModulesCollector),
        Box::new(sdks::SdkCollector),
        Box::new(caches::CachesCollector),
    ]
}

/// The collector responsible for items of `kind`.
pub fn collector_for(kind: ItemKind) -> Option<Box<dyn Collector>> {
    let id = match kind {
        ItemKind::Win32 | ItemKind::Msi => "registry",
        ItemKind::Appx => "appx",
        ItemKind::Service => "services",
        ItemKind::Process => "processes",
        ItemKind::Startup => "startup",
        ItemKind::Task => "tasks",
        ItemKind::Driver => "drivers",
        ItemKind::Feature => "features",
        ItemKind::Capability => "capabilities",
        ItemKind::Update => "updates",
        ItemKind::Package => "packages",
        ItemKind::Module => "modules",
        ItemKind::Sdk | ItemKind::Runtime => "sdks",
        ItemKind::Cache => "caches",
    };
    all().into_iter().find(|c| c.id() == id)
}

pub struct CollectorOutput<'a> {
    pub collector: &'a dyn Collector,
    pub result: CollectResult<Vec<Item>>,
    /// The collector did not run because it needs administrator rights.
    pub skipped: bool,
    pub elapsed: Duration,
}

/// Runs all collectors on scoped threads and reports each one as soon as it finishes.
pub fn scan_parallel<F>(collectors: &[Box<dyn Collector>], on_output: F)
where
    F: Fn(CollectorOutput<'_>) + Sync,
{
    let elevated = util::is_elevated();
    std::thread::scope(|scope| {
        for c in collectors {
            let on_output = &on_output;
            if c.requires_admin() && !elevated {
                on_output(CollectorOutput {
                    collector: c.as_ref(),
                    result: Err(CollectError("Requires an administrator session".into())),
                    skipped: true,
                    elapsed: Duration::ZERO,
                });
                continue;
            }
            scope.spawn(move || {
                let start = Instant::now();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut items = c.collect()?;
                    trust::assess(&mut items);
                    Ok(items)
                }))
                .unwrap_or_else(|_| Err(CollectError("collector panicked".into())));
                on_output(CollectorOutput {
                    collector: c.as_ref(),
                    result,
                    skipped: false,
                    elapsed: start.elapsed(),
                });
            });
        }
    });
}
