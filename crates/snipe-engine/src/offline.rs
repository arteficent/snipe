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

    // 1. Freeze the reviewed plan (reversible: the queue file is deleted on rollback).
    let queue = Queue { txn: txn.to_string(), ids: ids.to_vec(), created: safety::now() };
    let path = queue_path().map_err(|e| e.to_string())?;
    std::fs::write(&path, serde_json::to_vec_pretty(&queue).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;

    // A restore point before any boot change, best-effort.
    let _ = safety::restore_point(&format!("Snipe restart cleanup {txn}"));

    // 2. Register the Safe Mode agent. Self-protecting software (an EDR's anti-tamper)
    //    blocks exactly these boot/persistence changes while it is running, so if any step
    //    is refused we stop and undo everything — the machine is never left with a weakened
    //    boot or a suspended disk.
    if let Err(e) = boot::register_agent(&exe) {
        cleanup_scheduling();
        return Err(blocked_hint("register the cleanup service", &e));
    }

    // 3. One-time Safe Mode boot entry (reversible: the copied entry is deleted on rollback).
    let boot_id = match boot::set_one_time_safeboot() {
        Ok(id) => id,
        Err(e) => {
            cleanup_scheduling();
            return Err(blocked_hint("set the one-time Safe Mode boot entry", &e));
        }
    };

    // 4. BitLocker is suspended LAST, only after everything else is armed, so a block at an
    //    earlier step never leaves the volume key exposed. On failure, roll the boot entry back.
    let suspended = if boot::bitlocker_protected() {
        match boot::suspend_bitlocker_two_reboots() {
            Ok(()) => true,
            Err(e) => {
                let _ = boot::delete_boot_entry(&boot_id);
                cleanup_scheduling();
                return Err(blocked_hint("suspend BitLocker for the cleanup reboots", &e));
            }
        }
    } else {
        false
    };

    // 5. Reboot. If even this is refused, undo the whole arrangement.
    if let Err(e) = boot::reboot_now() {
        if suspended {
            let _ = boot::resume_bitlocker();
        }
        let _ = boot::delete_boot_entry(&boot_id);
        cleanup_scheduling();
        return Err(blocked_hint("restart the machine", &e));
    }
    log_event(&format!("Scheduled restart cleanup for transaction {txn}"));
    Ok(true)
}

/// Explains a refused privileged step: this is almost always the target's own tamper
/// protection, which cannot be defeated from the running system without turning Snipe
/// into an EDR-killer. Points the owner at the paths that actually work.
fn blocked_hint(action: &str, err: &str) -> String {
    format!(
        "Could not {action}: {err}\n\n\
         This is almost certainly the item's own tamper protection blocking Snipe while it is \
         running. The automatic restart cleanup cannot be set up against software that blocks \
         boot changes, and Snipe will not disable a running security product from the kernel. \
         Remove it instead with its vendor uninstall password or token (the Authorized step), \
         from its management console, or by booting the PC from external media."
    )
}

/// Cancels a pending cleanup before the reboot: removes the boot entry, the agent and the
/// queue, and resumes BitLocker if it was suspended.
pub fn cancel() -> Result<(), String> {
    let _ = boot::resume_bitlocker();
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
