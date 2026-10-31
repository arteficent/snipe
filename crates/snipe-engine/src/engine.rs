//! Request handler shared by the in-process engine (UI) and the elevated broker.

use crate::protocol::*;
use crate::{safety, traces, uninstall};
use serde::Serialize;
use snipe_core::{Item, ItemKind};
use std::collections::HashMap;
use std::sync::mpsc;
use std::time::Instant;

#[derive(Default)]
pub struct Engine {
    inventory: HashMap<String, Item>,
    scanned: bool,
}

fn json<T: Serialize>(value: T) -> Result<serde_json::Value, String> {
    serde_json::to_value(value).map_err(|e| e.to_string())
}

impl Engine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_inventory(&mut self, items: Vec<Item>) {
        self.inventory = items.into_iter().map(|i| (i.id.clone(), i)).collect();
        self.scanned = true;
    }

    pub fn items(&self) -> Vec<Item> {
        self.inventory.values().cloned().collect()
    }

    pub fn get(&self, id: &str) -> Option<&Item> {
        self.inventory.get(id)
    }

    /// Runs every collector, streaming events, and replaces the inventory.
    pub fn scan(&mut self, emit: &mut dyn FnMut(ScanEvent)) -> usize {
        let start = Instant::now();
        let collectors = snipe_collectors::all();
        emit(ScanEvent::Started {
            collectors: collectors
                .iter()
                .map(|c| CollectorInfo { id: c.id().into(), label: c.label().into(), requires_admin: c.requires_admin() })
                .collect(),
            elevated: snipe_collectors::util::is_elevated(),
        });
        let (tx, rx) = mpsc::channel::<ScanEvent>();
        let mut items = Vec::new();
        std::thread::scope(|s| {
            s.spawn(move || {
                snipe_collectors::scan_parallel(&collectors, |out| {
                    let elapsed_ms = out.elapsed.as_millis() as u64;
                    let collector = out.collector.id().to_string();
                    let event = match out.result {
                        Ok(items) => ScanEvent::Batch { collector, items, elapsed_ms },
                        Err(e) => ScanEvent::Failed { collector, error: e.0, elapsed_ms, skipped: out.skipped },
                    };
                    let _ = tx.send(event);
                });
            });
            for event in rx {
                if let ScanEvent::Batch { items: batch, .. } = &event {
                    items.extend(batch.iter().cloned());
                }
                emit(event);
            }
        });
        let total = items.len();
        self.set_inventory(items);
        emit(ScanEvent::Finished { total, elapsed_ms: start.elapsed().as_millis() as u64 });
        total
    }

    fn item(&mut self, id: &str) -> Result<Item, String> {
        if !self.scanned {
            self.scan(&mut |_| {});
        }
        self.inventory.get(id).cloned().ok_or_else(|| "Item not found; refresh the inventory and try again.".into())
    }

    /// Re-runs the item's collector to see whether it is still installed.
    fn still_present(&mut self, item: &Item) -> bool {
        let Some(collector) = snipe_collectors::collector_for(item.kind) else { return false };
        let Ok(items) = collector.collect() else { return true };
        let present = items.iter().any(|i| i.id == item.id);
        if !present {
            self.inventory.remove(&item.id);
        }
        present
    }

    fn recorded_removal(&mut self, item: &Item, options: &ExecOptions) -> Result<ExecOutcome, String> {
        let method = item.uninstall.get(options.method).ok_or("unknown removal method")?;
        let target = traces::method_target(method).ok_or("not a recorded removal")?;
        let leftover = Leftover {
            id: target.id(),
            display: target.display(),
            target,
            score: 100,
            reasons: vec!["selected for removal".into()],
            size_bytes: None,
            preselected: true,
        };
        let id = leftover.id.clone();
        let txn = safety::create(item, vec![leftover]).map_err(|e| e.to_string())?;
        let report = safety::clean(&txn, &[id]).map_err(|e| e.to_string())?;
        if let Some((_, error)) = report.failed.first() {
            return Err(error.clone());
        }
        Ok(ExecOutcome {
            success: true,
            reboot_required: report.reboot_required,
            message: "Removed (backed up, can be undone from History)".into(),
            txn: Some(txn),
            ..Default::default()
        })
    }

    pub fn handle(&mut self, request: Request, emit: &mut dyn FnMut(ScanEvent)) -> Result<serde_json::Value, String> {
        match request {
            Request::Ping => json(snipe_collectors::util::is_elevated()),
            Request::Scan => json(self.scan(emit)),
            Request::Plan { id } => json(uninstall::plan(&self.item(&id)?)),
            Request::RestorePoint { description } => json(safety::restore_point(&description)?),
            Request::Execute { id, options } => {
                let item = self.item(&id)?;
                let method = item.uninstall.get(options.method).ok_or("unknown removal method")?;
                let mut outcome = if traces::method_target(method).is_some() {
                    if let Some(reason) = item.removal_block() {
                        return Err(reason.into());
                    }
                    self.recorded_removal(&item, &options)?
                } else {
                    uninstall::execute(&item, &options)?
                };
                outcome.still_present = self.still_present(&item);
                json(outcome)
            }
            Request::Leftovers { id, forced } => {
                let item = self.item(&id)?;
                if forced && !uninstall::plan(&item).can_force {
                    return Err("Force removal is not available for this item.".into());
                }
                let all: Vec<Item> = self.inventory.values().cloned().collect();
                let leftovers = traces::find(&item, &all);
                let txn = safety::create(&item, leftovers.clone()).map_err(|e| e.to_string())?;
                json(LeftoverReport { txn, leftovers })
            }
            Request::Clean { txn, ids } => json(safety::clean(&txn, &ids).map_err(|e| e.to_string())?),
            Request::History => json(safety::history().map_err(|e| e.to_string())?),
            Request::Undo { txn } => json(safety::undo(&txn).map_err(|e| e.to_string())?),
            Request::Terminate { id } => {
                let item = self.item(&id)?;
                if item.kind != ItemKind::Process {
                    return Err("not a process".into());
                }
                let pid: u32 = item
                    .source
                    .rsplit('\\')
                    .next()
                    .and_then(|p| p.parse().ok())
                    .ok_or("invalid process id")?;
                if item.protection == snipe_core::Protection::Locked {
                    return Err("This process is protected.".into());
                }
                // Guard against PID reuse since the scan.
                let current = uninstall::image_path(pid).unwrap_or_default();
                if !current.to_ascii_lowercase().ends_with(&format!("\\{}", item.name.to_ascii_lowercase())) {
                    return Err("The process has already exited.".into());
                }
                uninstall::terminate(pid)?;
                self.inventory.remove(&id);
                json(())
            }
            Request::Shutdown => json(()),
            Request::Threat { id } => {
                let item = self.item(&id)?;
                let all: Vec<Item> = self.inventory.values().cloned().collect();
                let leftovers = threat_plan(&item, &all)?;
                let txn = safety::create(&item, leftovers.clone()).map_err(|e| e.to_string())?;
                json(LeftoverReport { txn, leftovers })
            }
            Request::DefenderScan { id } => {
                let item = self.item(&id)?;
                let exe = item.executable.as_deref().ok_or("No executable is known for this item.")?;
                json(uninstall::defender_scan(exe)?)
            }
        }
    }
}

fn leftover(target: Target, score: u8, reason: &str) -> Leftover {
    Leftover {
        id: target.id(),
        display: target.display(),
        target,
        score,
        reasons: vec![reason.to_string()],
        size_bytes: None,
        preselected: score >= traces::PRESELECT,
    }
}

/// The flagged executable, running instances, and every autostart entry that launches it.
fn threat_plan(item: &Item, inventory: &[Item]) -> Result<Vec<Leftover>, String> {
    let exe = item.executable.clone().ok_or("No executable is known for this item.")?;
    if item.risk < snipe_core::risk::UNTRUSTED {
        return Err("This item is not flagged as untrusted.".into());
    }
    if snipe_core::deny::is_denied_path(&exe) {
        return Err("The file is inside a protected Windows folder. Run a Microsoft Defender Offline scan instead.".into());
    }
    let mut out = Vec::new();
    if !uninstall::processes_with_image(&exe).is_empty() {
        out.push(leftover(Target::Process { path: exe.clone() }, 100, "running instances"));
    }
    for other in inventory {
        let launches = other.executable.as_deref().is_some_and(|e| e.eq_ignore_ascii_case(&exe));
        if !launches || !matches!(other.kind, ItemKind::Startup | ItemKind::Task | ItemKind::Service) {
            continue;
        }
        for method in &other.uninstall {
            if let Some(target) = traces::method_target(method) {
                out.push(leftover(target, 95, &format!("{} that launches it", other.kind.as_str())));
            }
        }
    }
    if std::path::Path::new(&exe).is_file() {
        let mut file = leftover(Target::File { path: exe.clone() }, 95, "the flagged executable");
        file.size_bytes = std::fs::metadata(&exe).ok().map(|m| m.len());
        out.push(file);
    }
    let lower = exe.to_ascii_lowercase();
    let user_writable = [r"\appdata\", r"\temp\", r"\users\public\", r"\downloads\", r"\programdata\"]
        .iter()
        .any(|p| lower.contains(p));
    if let Some(dir) = snipe_core::paths::parent_dir(&exe)
        && user_writable
        && !snipe_core::deny::is_denied_path(&dir)
    {
        let shared = inventory.iter().any(|o| {
            o.executable.as_deref().is_some_and(|e| {
                snipe_core::paths::is_under(e, &dir) && !e.eq_ignore_ascii_case(&exe) && o.risk < snipe_core::risk::UNTRUSTED
            })
        });
        if !shared {
            out.push(leftover(Target::Dir { path: dir }, 60, "folder containing the executable"));
        }
    }
    let mut seen = std::collections::HashSet::new();
    out.retain(|l| seen.insert(l.id.clone()));
    if out.is_empty() {
        return Err("Nothing left to remove; the file is already gone.".into());
    }
    Ok(out)
}
