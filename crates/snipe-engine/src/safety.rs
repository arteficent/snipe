//! Safety layer: transactions (journal), backups, quarantine, removal, undo and restore points.

use crate::protocol::{CleanReport, Leftover, Target, TxnSummary, UndoReport};
use crate::{exec, regio, store};
use serde::{Deserialize, Serialize};
use snipe_collectors::util::{is_reparse_point, system32, to_wide};
use snipe_core::cmdline::is_safe_identifier;
use snipe_core::{Item, RegPath, deny, paths};
use std::io;
use std::path::{Path, PathBuf};
use windows::Win32::Foundation::{LPARAM, WPARAM};
use windows::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
use windows::Win32::System::Restore::{
    APPLICATION_UNINSTALL, BEGIN_SYSTEM_CHANGE, END_SYSTEM_CHANGE, RESTOREPOINTINFOW, SRSetRestorePointW,
    STATEMGRSTATUS,
};
use windows::Win32::UI::WindowsAndMessaging::{HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE};
use windows::core::PCWSTR;

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
enum Backup {
    Quarantine { original: String, stored: String },
    RegFile { file: String, wow32: bool },
    TaskXml { path: String, file: String },
    Env { file: String, wow32: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "camelCase", rename_all_fields = "camelCase")]
enum Status {
    Removed,
    RebootPending,
    Failed { error: String },
    Restored,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    leftover: String,
    target: Target,
    status: Status,
    backup: Option<Backup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Txn {
    id: String,
    created: u64,
    item: Item,
    leftovers: Vec<Leftover>,
    entries: Vec<Entry>,
    undone: bool,
}

fn txn_dir(id: &str) -> io::Result<PathBuf> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid transaction id"));
    }
    Ok(store::txn_root()?.join(id))
}

fn load(id: &str) -> io::Result<Txn> {
    let text = std::fs::read(txn_dir(id)?.join("manifest.json"))?;
    serde_json::from_slice(&text).map_err(io::Error::other)
}

/// Journal write: the manifest is replaced atomically after every step.
fn save(txn: &Txn) -> io::Result<()> {
    let dir = txn_dir(&txn.id)?;
    std::fs::create_dir_all(&dir)?;
    let tmp = dir.join("manifest.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(txn).map_err(io::Error::other)?)?;
    std::fs::rename(tmp, dir.join("manifest.json"))
}

/// Records a new transaction with the leftovers found for `item`.
pub fn create(item: &Item, leftovers: Vec<Leftover>) -> io::Result<String> {
    let nonce = snipe_core::fnv1a(format!("{}{:?}{}", item.id, std::time::Instant::now(), std::process::id()).bytes());
    let id = format!("{:x}-{:08x}", now(), nonce as u32);
    save(&Txn { id: id.clone(), created: now(), item: item.clone(), leftovers, entries: Vec::new(), undone: false })?;
    Ok(id)
}

pub fn clean(id: &str, ids: &[String]) -> io::Result<CleanReport> {
    let mut txn = load(id)?;
    if txn.undone {
        return Err(io::Error::other("transaction was already undone"));
    }
    let dir = txn_dir(id)?;
    let mut report = CleanReport::default();
    let selected: Vec<Leftover> = txn.leftovers.iter().filter(|l| ids.contains(&l.id)).cloned().collect();
    // Stop processes first, then children before parents so nested folders and keys are handled cleanly.
    let mut ordered = selected;
    ordered.sort_by_key(|l| (!matches!(l.target, Target::Process { .. }), std::cmp::Reverse(l.display.len())));
    for leftover in ordered {
        if txn.entries.iter().any(|e| e.leftover == leftover.id && !matches!(e.status, Status::Failed { .. })) {
            continue;
        }
        let n = txn.entries.len();
        let (status, backup) = match remove(&leftover.target, &dir, n) {
            Ok((pending, backup)) => {
                report.removed += 1;
                report.reboot_required |= pending;
                (if pending { Status::RebootPending } else { Status::Removed }, backup)
            }
            Err(error) => {
                report.failed.push((leftover.id.clone(), error.clone()));
                (Status::Failed { error }, None)
            }
        };
        txn.entries.push(Entry { leftover: leftover.id.clone(), target: leftover.target.clone(), status, backup });
        save(&txn)?;
    }
    Ok(report)
}

pub fn undo(id: &str) -> io::Result<UndoReport> {
    let mut txn = load(id)?;
    if txn.undone {
        return Err(io::Error::other("transaction was already undone"));
    }
    let mut report = UndoReport::default();
    for i in (0..txn.entries.len()).rev() {
        let entry = &txn.entries[i];
        if !matches!(entry.status, Status::Removed | Status::RebootPending) {
            continue;
        }
        let result = match &entry.backup {
            Some(backup) => restore(backup),
            None => Err("no backup was taken".to_string()),
        };
        match result {
            Ok(()) => {
                report.restored += 1;
                txn.entries[i].status = Status::Restored;
            }
            Err(e) => report.failed.push(format!("{}: {e}", entry.target.display())),
        }
        save(&txn)?;
    }
    txn.undone = true;
    save(&txn)?;
    Ok(report)
}

pub fn history() -> io::Result<Vec<TxnSummary>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(store::txn_root()?)?.flatten() {
        let Ok(txn) = load(&entry.file_name().to_string_lossy()) else { continue };
        let removed = txn.entries.iter().filter(|e| matches!(e.status, Status::Removed | Status::RebootPending)).count();
        out.push(TxnSummary {
            can_undo: !txn.undone && removed > 0,
            id: txn.id,
            created: txn.created,
            item_name: txn.item.name,
            item_kind: txn.item.kind.as_str().to_string(),
            found: txn.leftovers.len(),
            removed,
            undone: txn.undone,
        });
    }
    out.sort_by_key(|t| std::cmp::Reverse(t.created));
    Ok(out)
}

/// Deletes quarantine/backups for transactions older than `days`.
pub fn purge_older_than(days: u64) {
    let Ok(root) = store::txn_root() else { return };
    let cutoff = now().saturating_sub(days * 86_400);
    for entry in std::fs::read_dir(root).into_iter().flatten().flatten() {
        if let Ok(txn) = load(&entry.file_name().to_string_lossy())
            && txn.created < cutoff
        {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Creates a System Restore point. Windows skips it if one was made in the last 24 hours.
pub fn restore_point(description: &str) -> Result<(), String> {
    let mut description_w = [0u16; 256];
    for (dst, src) in description_w.iter_mut().zip(description.encode_utf16().take(255)) {
        *dst = src;
    }
    let mut info = RESTOREPOINTINFOW {
        dwEventType: BEGIN_SYSTEM_CHANGE,
        dwRestorePtType: APPLICATION_UNINSTALL,
        llSequenceNumber: 0,
        szDescription: description_w,
    };
    let mut status = STATEMGRSTATUS::default();
    // SAFETY: both structs are fully initialised and outlive the calls.
    unsafe {
        if !SRSetRestorePointW(&info, &mut status).as_bool() {
            let code = { status.nStatus }.0;
            return Err(format!("System Restore is unavailable (error {code})"));
        }
        info.dwEventType = END_SYSTEM_CHANGE;
        info.llSequenceNumber = status.llSequenceNumber;
        let _ = SRSetRestorePointW(&info, &mut status);
    }
    Ok(())
}

fn broadcast_environment() {
    let text = to_wide("Environment");
    // SAFETY: the string outlives the (time-limited) broadcast.
    unsafe {
        let _ = SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            WPARAM(0),
            LPARAM(text.as_ptr() as isize),
            SMTO_ABORTIFHUNG,
            5000,
            None,
        );
    }
}

fn os_err(e: io::Error) -> String {
    e.to_string()
}

fn check_path(path: &str) -> Result<(), String> {
    if deny::is_denied_path(path) {
        return Err("protected location (deny-list)".into());
    }
    // Re-check after resolving links so `..`, junctions or 8.3 names can't sneak past.
    if let Ok(canonical) = std::fs::canonicalize(path) {
        let c = canonical.to_string_lossy();
        if deny::is_denied_path(&c) {
            return Err("resolves to a protected location".into());
        }
    }
    Ok(())
}

fn schedule_delete(path: &Path) -> bool {
    let wide = to_wide(&path.to_string_lossy());
    // SAFETY: valid NUL-terminated path; a null destination means delete.
    unsafe { MoveFileExW(PCWSTR(wide.as_ptr()), PCWSTR::null(), MOVEFILE_DELAY_UNTIL_REBOOT).is_ok() }
}

/// Copies a tree without following junctions/symlinks; unreadable files are skipped.
fn copy_tree(src: &Path, dst: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)?.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if is_reparse_point(&meta) {
            continue;
        }
        let to = dst.join(entry.file_name());
        if meta.is_dir() {
            let _ = copy_tree(&entry.path(), &to);
        } else {
            let _ = std::fs::copy(entry.path(), &to);
        }
    }
    Ok(())
}

/// Deletes a path (never following links); anything locked is scheduled for deletion at reboot.
/// Returns true if a reboot is needed to finish.
fn delete_or_schedule(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else { return false };
    if is_reparse_point(&meta) || !meta.is_dir() {
        let removed = if meta.is_dir() { std::fs::remove_dir(path) } else { std::fs::remove_file(path) };
        return removed.is_err() && schedule_delete(path);
    }
    let mut pending = false;
    for entry in std::fs::read_dir(path).into_iter().flatten().flatten() {
        pending |= delete_or_schedule(&entry.path());
    }
    if std::fs::remove_dir(path).is_err() {
        pending |= schedule_delete(path);
    }
    pending
}

/// Moves `src` into quarantine. Falls back to copy + delete (cross-volume or files in use).
fn quarantine(src: &Path, stored: &Path) -> io::Result<bool> {
    if let Some(parent) = stored.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if std::fs::rename(src, stored).is_ok() {
        return Ok(false);
    }
    let meta = std::fs::symlink_metadata(src)?;
    if !is_reparse_point(&meta) {
        if meta.is_dir() {
            copy_tree(src, stored)?;
        } else {
            std::fs::copy(src, stored)?;
        }
    }
    let pending = delete_or_schedule(src);
    if src.exists() && !pending {
        return Err(io::Error::other("could not delete or schedule deletion"));
    }
    Ok(pending)
}

fn backup_file(dir: &Path, sub: &str, n: usize, ext: &str) -> io::Result<PathBuf> {
    let folder = dir.join(sub);
    std::fs::create_dir_all(&folder)?;
    Ok(folder.join(format!("{n}.{ext}")))
}

fn is_env_key(key: &RegPath) -> bool {
    let k = key.key.to_ascii_lowercase();
    k == r"hklm\system\currentcontrolset\control\session manager\environment"
        || (k.starts_with(r"hku\") && k.ends_with(r"\environment") && k.matches('\\').count() == 2)
}

fn tasks_dir() -> PathBuf {
    system32("Tasks")
}

fn valid_task_path(path: &str) -> bool {
    path.starts_with('\\')
        && !path.contains("..")
        && !path.to_ascii_lowercase().starts_with(r"\microsoft\")
        && is_safe_identifier(path)
}

fn remove(target: &Target, dir: &Path, n: usize) -> Result<(bool, Option<Backup>), String> {
    match target {
        Target::Process { path } => {
            check_path(path)?;
            let mut errors = Vec::new();
            for p in crate::uninstall::processes_with_image(path) {
                if let Err(e) = crate::uninstall::terminate(p.pid) {
                    errors.push(format!("PID {}: {e}", p.pid));
                }
            }
            if errors.is_empty() { Ok((false, None)) } else { Err(errors.join("; ")) }
        }
        Target::File { path } | Target::Dir { path } => {
            check_path(path)?;
            let src = Path::new(path);
            if std::fs::symlink_metadata(src).is_err() {
                return Ok((false, None));
            }
            let stored = dir.join("files").join(n.to_string());
            let pending = quarantine(src, &stored).map_err(os_err)?;
            let backup = stored.exists().then(|| Backup::Quarantine {
                original: path.clone(),
                stored: stored.to_string_lossy().into_owned(),
            });
            Ok((pending, backup))
        }
        Target::RegKey { key } => {
            if deny::is_denied_key(&key.key) {
                return Err("protected registry key (deny-list)".into());
            }
            if !regio::exists(key) {
                return Ok((false, None));
            }
            let file = backup_file(dir, "reg", n, "reg").map_err(os_err)?;
            regio::export_key(key, &file).map_err(os_err)?;
            regio::delete_key(key).map_err(os_err)?;
            Ok((false, Some(Backup::RegFile { file: file.to_string_lossy().into_owned(), wow32: key.wow32 })))
        }
        Target::RegValue { key, name } => {
            if deny::is_denied_value(&key.key) {
                return Err("protected registry location (deny-list)".into());
            }
            let file = backup_file(dir, "reg", n, "reg").map_err(os_err)?;
            regio::export_value(key, name, &file).map_err(os_err)?;
            regio::delete_value(key, name).map_err(os_err)?;
            Ok((false, Some(Backup::RegFile { file: file.to_string_lossy().into_owned(), wow32: key.wow32 })))
        }
        Target::Service { name } => {
            if !is_safe_identifier(name) || name.contains('\\') {
                return Err("invalid service name".into());
            }
            let key = RegPath::new(format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{name}"), false);
            let image = regio::open(&key, false)
                .ok()
                .and_then(|k| k.get_value::<String, _>("ImagePath").ok())
                .unwrap_or_default();
            if let Some(exe) = paths::exe_from_command(&image)
                && paths::is_windows_path(&exe)
            {
                return Err("service binary is part of Windows".into());
            }
            let file = backup_file(dir, "reg", n, "reg").map_err(os_err)?;
            regio::export_key(&key, &file).map_err(os_err)?;
            let sc = system32("sc.exe");
            let _ = exec::run_tool(&sc, ["stop", name.as_str()]);
            std::thread::sleep(std::time::Duration::from_secs(2));
            let (code, out) = exec::run_tool(&sc, ["delete", name.as_str()]).map_err(os_err)?;
            // 1072 = marked for deletion; finishes once all handles close or at reboot.
            if code != 0 && code != 1072 {
                return Err(format!("sc delete failed ({code}): {}", exec::last_line(&out)));
            }
            Ok((code == 1072, Some(Backup::RegFile { file: file.to_string_lossy().into_owned(), wow32: false })))
        }
        Target::Task { path } => {
            if !valid_task_path(path) {
                return Err("invalid or protected task path".into());
            }
            let source = tasks_dir().join(path.trim_start_matches('\\'));
            let file = backup_file(dir, "tasks", n, "xml").map_err(os_err)?;
            std::fs::copy(&source, &file).map_err(os_err)?;
            let (code, out) =
                exec::run_tool(system32("schtasks.exe"), ["/delete", "/tn", path.as_str(), "/f"]).map_err(os_err)?;
            if code != 0 {
                return Err(format!("schtasks failed ({code}): {}", exec::last_line(&out)));
            }
            Ok((false, Some(Backup::TaskXml { path: path.clone(), file: file.to_string_lossy().into_owned() })))
        }
        Target::EnvPath { key, entry } => {
            if !is_env_key(key) {
                return Err("not an environment key".into());
            }
            let file = backup_file(dir, "reg", n, "reg").map_err(os_err)?;
            regio::export_value(key, "Path", &file).map_err(os_err)?;
            let (vtype, bytes) = regio::read_raw(key, "Path").map_err(os_err)?;
            let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
            let text = String::from_utf16_lossy(&units);
            let norm = |s: &str| s.trim().trim_end_matches('\\').to_ascii_lowercase();
            let wanted = norm(entry);
            let kept: Vec<&str> =
                text.trim_end_matches('\0').split(';').filter(|p| norm(p) != wanted).collect();
            let new_text = format!("{}\0", kept.join(";"));
            let new_bytes = new_text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            regio::write_raw(key, "Path", vtype, new_bytes).map_err(os_err)?;
            broadcast_environment();
            Ok((false, Some(Backup::Env { file: file.to_string_lossy().into_owned(), wow32: key.wow32 })))
        }
    }
}

fn restore(backup: &Backup) -> Result<(), String> {
    match backup {
        Backup::Quarantine { original, stored } => {
            let dst = Path::new(original);
            if std::fs::symlink_metadata(dst).is_ok() {
                return Err("something already exists at the original location".into());
            }
            if let Some(parent) = dst.parent() {
                std::fs::create_dir_all(parent).map_err(os_err)?;
            }
            let src = Path::new(stored);
            if std::fs::rename(src, dst).is_ok() {
                return Ok(());
            }
            if src.is_dir() { copy_tree(src, dst) } else { std::fs::copy(src, dst).map(|_| ()) }.map_err(os_err)
        }
        Backup::RegFile { file, wow32 } => regio::import(Path::new(file), *wow32).map_err(os_err),
        Backup::Env { file, wow32 } => {
            regio::import(Path::new(file), *wow32).map_err(os_err)?;
            broadcast_environment();
            Ok(())
        }
        Backup::TaskXml { path, file } => {
            let (code, out) = exec::run_tool(
                system32("schtasks.exe"),
                ["/create", "/tn", path.as_str(), "/xml", file.as_str(), "/f"],
            )
            .map_err(os_err)?;
            if code == 0 { Ok(()) } else { Err(format!("schtasks failed ({code}): {}", exec::last_line(&out))) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_task_paths_and_env_keys() {
        assert!(valid_task_path(r"\Vendor\Updater"));
        assert!(!valid_task_path(r"\Microsoft\Windows\Defrag"));
        assert!(!valid_task_path(r"Vendor"));
        assert!(!valid_task_path(r"\..\x"));
        assert!(is_env_key(&RegPath::new(r"HKU\S-1-5-21-1\Environment", false)));
        assert!(!is_env_key(&RegPath::new(r"HKU\S-1-5-21-1\Software\Environment", false)));
    }

    #[test]
    fn refuses_denied_paths() {
        assert!(check_path(r"C:\Windows").is_err());
        assert!(check_path(r"C:\Program Files").is_err());
    }
}
