//! Automated restart-time (Safe Mode) cleanup (§5.4).
//!
//! `schedule` freezes a reviewed transaction into a queue, sets up a one-time Safe
//! Mode boot and reboots. On the next (Safe Mode) boot the Snipe binary is started as
//! `--offline-agent`; `run_agent` deletes the one-time boot entry first, runs the same
//! journaled `safety::clean` for the queued targets unattended, then reboots back to
//! normal mode. No protection is bypassed: in Safe Mode the self-protecting software
//! never starts.

use crate::{boot, safety, store};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::PathBuf;
use std::time::Duration;

/// Hard limit for one agent run so the machine never stalls in Safe Mode.
const WATCHDOG: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Queue {
    txn: String,
    ids: Vec<String>,
    created: u64,
}

fn queue_path() -> io::Result<PathBuf> {
    Ok(store::offline_root()?.join("pending.json"))
}

/// Freezes the plan, sets up the one-time Safe Mode boot and reboots immediately.
/// Returns true once the machine has been told to restart.
pub fn schedule(txn: &str, ids: &[String]) -> Result<bool, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe = exe.to_string_lossy().into_owned();

    let queue = Queue { txn: txn.to_string(), ids: ids.to_vec(), created: safety::now() };
    let path = queue_path().map_err(|e| e.to_string())?;
    std::fs::write(&path, serde_json::to_vec_pretty(&queue).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;

    // A restore point before any boot change, best-effort.
    let _ = safety::restore_point(&format!("Snipe restart cleanup {txn}"));

    if boot::bitlocker_protected() {
        boot::suspend_bitlocker_two_reboots()?;
    }
    boot::register_agent(&exe).inspect_err(|_| cleanup_scheduling())?;
    boot::set_one_time_safeboot().inspect_err(|_| cleanup_scheduling())?;
    log_event(&format!("Scheduled restart cleanup for transaction {txn}"));

    boot::reboot_now()?;
    Ok(true)
}

/// Cancels a pending cleanup before the reboot (removes the boot entry, agent and queue).
pub fn cancel() -> Result<(), String> {
    cleanup_scheduling();
    Ok(())
}

fn cleanup_scheduling() {
    boot::unregister_agent();
    if let Ok(path) = queue_path() {
        let _ = std::fs::remove_file(path);
    }
}

/// Entry point of `snipe.exe --offline-agent`, run by the Safe Mode service.
/// It is unattended: no window, no input, and it reboots to normal mode when done.
pub fn run_agent() -> Result<(), String> {
    // Fail-safe: whatever happens next, make sure the one-time boot entry is gone so the
    // following boot is normal. `bcdedit /bootsequence` is already one-shot; unregister
    // the agent and drop the queue so nothing repeats.
    let path = queue_path().map_err(|e| e.to_string())?;
    let queue: Queue = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| e.to_string())?,
        Err(_) => {
            finish();
            return Ok(());
        }
    };

    let start = std::time::Instant::now();
    // Run the queued removal through the same journaled, undoable path.
    let result = safety::clean(&queue.txn, &queue.ids);
    if start.elapsed() > WATCHDOG {
        log_event("Offline cleanup hit the watchdog time limit");
    }
    match result {
        Ok(report) => log_event(&format!(
            "Offline cleanup removed {} item(s), {} failed",
            report.removed,
            report.failed.len()
        )),
        Err(e) => log_event(&format!("Offline cleanup error: {e}")),
    }

    finish();
    Ok(())
}

/// Clears the agent registration and queue, then reboots to normal mode.
fn finish() {
    cleanup_scheduling();
    let _ = boot::reboot_now();
}

/// Best-effort entry in the Windows Application event log.
fn log_event(message: &str) {
    let _ = crate::exec::run_tool(
        snipe_collectors::util::system32("eventcreate.exe"),
        ["/T", "INFORMATION", "/ID", "1000", "/L", "APPLICATION", "/SO", "Snipe", "/D", message],
    );
}
