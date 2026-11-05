//! Low-level helpers for the automated restart-time cleanup (§5.4): a one-time
//! Safe Mode boot entry, BitLocker suspension and the offline agent service.
//!
//! Everything here shells out to the signed in-box tools (`bcdedit`, `manage-bde`,
//! `sc`, `reg`, `shutdown`) through the elevated broker. Nothing runs on import;
//! the functions are called only when the owner schedules a Tier 2 removal.

use crate::exec::{self, run_tool};
use snipe_collectors::util::system32;

const AGENT_SERVICE: &str = "SnipeOfflineAgent";
const SAFEBOOT_MINIMAL: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\SnipeOfflineAgent";

fn tool(name: &str, args: &[&str]) -> Result<(i32, String), String> {
    run_tool(system32(name), args.iter().copied()).map_err(|e| e.to_string())
}

/// True when the OS volume is protected by BitLocker (and therefore needs suspension
/// before the boot configuration is changed).
pub fn bitlocker_protected() -> bool {
    tool("manage-bde.exe", &["-status", "C:"])
        .map(|(_, out)| {
            let o = out.to_ascii_lowercase();
            o.contains("protection on")
        })
        .unwrap_or(false)
}

/// Suspends BitLocker for the two cleanup reboots so the modified boot entry does not
/// trigger a recovery prompt. Protection resumes automatically afterwards.
pub fn suspend_bitlocker_two_reboots() -> Result<(), String> {
    let (code, out) = tool("manage-bde.exe", &["-protectors", "-disable", "C:", "-RebootCount", "2"])?;
    if code != 0 {
        return Err(format!("manage-bde failed ({code}): {}", exec::last_line(&out)));
    }
    Ok(())
}

/// Creates a one-time Safe Mode (minimal) boot entry using a copied BCD object and
/// `bootsequence`, so a failure or power loss still boots normally next time.
/// Returns the identifier of the copied entry.
pub fn set_one_time_safeboot() -> Result<String, String> {
    let (code, out) = tool("bcdedit.exe", &["/copy", "{current}", "/d", "Snipe cleanup"])?;
    if code != 0 {
        return Err(format!("bcdedit /copy failed ({code}): {}", exec::last_line(&out)));
    }
    // Output looks like: The entry was successfully copied to {GUID}.
    let id = out
        .split('{')
        .nth(1)
        .and_then(|s| s.split('}').next())
        .map(|g| format!("{{{g}}}"))
        .ok_or("could not read the copied boot entry id")?;
    let (c1, o1) = tool("bcdedit.exe", &["/set", &id, "safeboot", "minimal"])?;
    if c1 != 0 {
        let _ = delete_boot_entry(&id);
        return Err(format!("bcdedit /set safeboot failed ({c1}): {}", exec::last_line(&o1)));
    }
    let (c2, o2) = tool("bcdedit.exe", &["/bootsequence", &id])?;
    if c2 != 0 {
        let _ = delete_boot_entry(&id);
        return Err(format!("bcdedit /bootsequence failed ({c2}): {}", exec::last_line(&o2)));
    }
    Ok(id)
}

pub fn delete_boot_entry(id: &str) -> Result<(), String> {
    let (code, out) = tool("bcdedit.exe", &["/delete", id, "/cleanup"])?;
    if code != 0 {
        return Err(format!("bcdedit /delete failed ({code}): {}", exec::last_line(&out)));
    }
    Ok(())
}

/// Re-enables BitLocker protectors, undoing a suspension if the schedule is rolled back.
pub fn resume_bitlocker() -> Result<(), String> {
    let (code, out) = tool("manage-bde.exe", &["-protectors", "-enable", "C:"])?;
    if code != 0 {
        return Err(format!("manage-bde enable failed ({code}): {}", exec::last_line(&out)));
    }
    Ok(())
}

/// Registers the offline agent as a LocalSystem service that auto-starts in Safe Mode
/// minimal. `exe` is the path to the running Snipe binary.
pub fn register_agent(exe: &str) -> Result<(), String> {
    let bin = format!("\"{exe}\" --offline-agent");
    let (code, out) = tool(
        "sc.exe",
        &["create", AGENT_SERVICE, "binPath=", &bin, "start=", "auto", "obj=", "LocalSystem"],
    )?;
    if code != 0 {
        return Err(format!("sc create failed ({code}): {}", exec::last_line(&out)));
    }
    // Allow the service to start in Safe Mode minimal.
    let (rc, ro) = tool("reg.exe", &["add", SAFEBOOT_MINIMAL, "/ve", "/t", "REG_SZ", "/d", "Service", "/f"])?;
    if rc != 0 {
        return Err(format!("reg add SafeBoot failed ({rc}): {}", exec::last_line(&ro)));
    }
    Ok(())
}

/// Removes the agent service and its Safe Mode registration.
pub fn unregister_agent() {
    let _ = tool("sc.exe", &["delete", AGENT_SERVICE]);
    let _ = tool("reg.exe", &["delete", SAFEBOOT_MINIMAL, "/f"]);
}

/// Restarts the machine now.
pub fn reboot_now() -> Result<(), String> {
    let (code, out) = tool("shutdown.exe", &["/r", "/t", "0"])?;
    if code != 0 {
        return Err(format!("shutdown failed ({code}): {}", exec::last_line(&out)));
    }
    Ok(())
}
