//! Uninstall orchestration: preflight plan, stopping processes, and running each removal method.

use crate::exec::{self, run_in_job, run_tool};
use crate::protocol::{ExecOptions, ExecOutcome, MethodInfo, Plan, ProcInfo};
use crate::traces;
use snipe_collectors::util::{env_path, system32, wide_to_string};
use snipe_core::cmdline::{is_safe_identifier, is_safe_package_name, msi_product_from_command, split_command};
use snipe_core::{Item, ItemKind, Protection, Scope, UninstallMethod, deny, paths};
use std::path::{Path, PathBuf};
use std::time::Duration;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    IsProcessCritical, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    QueryFullProcessImageNameW, TerminateProcess,
};
use windows::core::{BOOL, HSTRING, PWSTR};

const UNINSTALLER_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);

/// Methods that run in the standard-user context: user-writable registrations must never be
/// executed with administrator rights.
pub fn runs_unelevated(item: &Item, method: &UninstallMethod) -> bool {
    item.scope == Scope::User
        && matches!(method, UninstallMethod::Command { .. } | UninstallMethod::PackageManager { .. } | UninstallMethod::Appx { .. })
}

pub fn plan(item: &Item) -> Plan {
    let mut warnings = Vec::new();
    match item.protection {
        Protection::Shared => warnings.push(
            "Other programs may depend on this shared component. Removing it can break them.".to_string(),
        ),
        Protection::System if item.removal_block().is_none() => warnings.push(
            "This is a Windows component. It will be removed with DISM; a restart may be required.".to_string(),
        ),
        _ => {}
    }
    if item.hidden && matches!(item.kind, ItemKind::Win32 | ItemKind::Msi) {
        warnings.push("Windows marks this entry as a system component or update of another product.".into());
    }
    let methods = item
        .uninstall
        .iter()
        .enumerate()
        .map(|(index, m)| MethodInfo {
            index,
            label: m.label(),
            runs_unelevated: runs_unelevated(item, m),
            undoable: traces::method_target(m).is_some(),
        })
        .collect();
    if item.uninstall.iter().any(|m| matches!(m, UninstallMethod::CleanDir { .. })) {
        warnings.push("Cleaning a cache deletes its contents permanently (no quarantine).".into());
    }
    let processes = item
        .install_location
        .as_deref()
        .filter(|d| !deny::is_denied_path(d))
        .map(processes_in)
        .unwrap_or_default();
    if !processes.is_empty() {
        warnings.push(format!("{} running process(es) will be closed first.", processes.len()));
    }
    let can_force = matches!(item.kind, ItemKind::Win32 | ItemKind::Msi | ItemKind::Appx)
        && !matches!(item.protection, Protection::Locked | Protection::System);
    Plan { item: item.clone(), blocked: item.removal_block().map(str::to_string), warnings, methods, processes, can_force }
}

struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: owned handle closed once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

pub fn image_path(pid: u32) -> Option<String> {
    // SAFETY: handle closed by Owned; buffer length passed explicitly.
    unsafe {
        let h = Owned(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?);
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len).ok()?;
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// Processes whose executable lives under `dir`.
pub fn processes_in(dir: &str) -> Vec<ProcInfo> {
    processes_matching(|path| paths::is_under(path, dir))
}

/// Processes running exactly this image.
pub fn processes_with_image(image: &str) -> Vec<ProcInfo> {
    processes_matching(|path| path.eq_ignore_ascii_case(image))
}

fn processes_matching(matches: impl Fn(&str) -> bool) -> Vec<ProcInfo> {
    let mut out = Vec::new();
    let me = std::process::id();
    // SAFETY: standard Toolhelp enumeration.
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else { return out };
        let snap = Owned(snap);
        let mut entry = PROCESSENTRY32W { dwSize: size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut ok = Process32FirstW(snap.0, &mut entry).is_ok();
        while ok {
            let pid = entry.th32ProcessID;
            if pid > 4 && pid != me
                && let Some(path) = image_path(pid)
                && matches(&path)
            {
                out.push(ProcInfo { pid, name: wide_to_string(&entry.szExeFile), path });
            }
            ok = Process32NextW(snap.0, &mut entry).is_ok();
        }
    }
    out
}

/// Scans a single file with Microsoft Defender (no remediation) and reports the verdict.
pub fn defender_scan(path: &str) -> Result<String, String> {
    if !Path::new(path).is_file() {
        return Err("the file no longer exists".into());
    }
    let tool = env_path("ProgramFiles")
        .map(|p| p.join(r"Windows Defender\MpCmdRun.exe"))
        .filter(|p| p.is_file())
        .ok_or("Microsoft Defender is not available on this system")?;
    let (code, out) = run_tool(&tool, ["-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"])
        .map_err(|e| e.to_string())?;
    match code {
        0 => Ok("Microsoft Defender found no threats in this file.".into()),
        2 => {
            let detail: Vec<&str> = out.lines().map(str::trim).filter(|l| l.to_ascii_lowercase().contains("threat")).collect();
            Ok(format!("Microsoft Defender detected a threat. {}", detail.join(" ")))
        }
        _ => Err(format!("Defender scan failed ({code}): {}", exec::last_line(&out))),
    }
}

/// Terminates a process, refusing critical system processes.
pub fn terminate(pid: u32) -> Result<(), String> {
    if pid <= 4 || pid == std::process::id() {
        return Err("refusing to terminate this process".into());
    }
    // SAFETY: handle closed by Owned.
    unsafe {
        let h = Owned(
            OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
                .map_err(|e| format!("cannot open process: {}", e.message()))?,
        );
        let mut critical = BOOL(0);
        if IsProcessCritical(h.0, &mut critical).is_ok() && critical.as_bool() {
            return Err("this is a critical Windows process; terminating it would crash the system".into());
        }
        TerminateProcess(h.0, 1).map_err(|e| e.message().to_string())
    }
}

fn outcome(code: i64, ok_codes: &[i64], reboot_codes: &[i64], what: &str, detail: &str) -> ExecOutcome {
    let success = ok_codes.contains(&code) || reboot_codes.contains(&code);
    let reboot = reboot_codes.contains(&code);
    let message = if success {
        format!("{what} finished{}", if reboot { "; a restart is required to complete it" } else { "" })
    } else if detail.is_empty() {
        format!("{what} failed with exit code {code}")
    } else {
        format!("{what} failed with exit code {code}: {detail}")
    };
    ExecOutcome { success, exit_code: Some(code), reboot_required: reboot, message, ..Default::default() }
}

fn silent_switch(exe: &str) -> Option<&'static str> {
    let file = Path::new(exe).file_name()?.to_string_lossy().to_ascii_lowercase();
    if file.starts_with("unins") && file.len() == 12 && file.get(5..8).is_some_and(|d| d.chars().all(|c| c.is_ascii_digit())) {
        return Some("/VERYSILENT /SUPPRESSMSGBOXES /NORESTART");
    }
    let bytes = std::fs::read(exe).ok()?;
    let head = &bytes[..bytes.len().min(4 << 20)];
    head.windows(8).any(|w| w == b"Nullsoft").then_some("/S")
}

fn run_msi(product_code: &str, silent: bool) -> Result<ExecOutcome, String> {
    if !snipe_core::cmdline::is_guid(product_code) {
        return Err("invalid product code".into());
    }
    let args = format!("/x {product_code} /norestart {}", if silent { "/qn" } else { "/qb" });
    let r = run_in_job(&system32("msiexec.exe").to_string_lossy(), &args, UNINSTALLER_TIMEOUT).map_err(|e| e.to_string())?;
    if r.timed_out {
        return Err("Windows Installer is still running after the timeout".into());
    }
    let code = r.exit_code as i64;
    let mut out = outcome(code, &[0, 1605, 1614], &[3010, 1641], "Windows Installer", "");
    if code == 1602 {
        out.message = "The uninstall was cancelled.".into();
    }
    Ok(out)
}

fn run_command(command: &str, quiet: bool, silent: bool) -> Result<ExecOutcome, String> {
    if let Some(code) = msi_product_from_command(command) {
        return run_msi(&code, silent || quiet);
    }
    let split = split_command(command).ok_or("the uninstall command is empty")?;
    if !Path::new(&split.exe).is_file() {
        return Err(format!(
            "The uninstaller was not found at {}. Use \"Force remove\" to clean up what is left.",
            split.exe
        ));
    }
    let mut args = split.args;
    if silent
        && !quiet
        && let Some(extra) = silent_switch(&split.exe)
        && !args.to_ascii_lowercase().contains(&extra.split(' ').next().unwrap_or(extra).to_ascii_lowercase())
    {
        args = format!("{args} {extra}").trim().to_string();
    }
    let r = run_in_job(&split.exe, &args, UNINSTALLER_TIMEOUT).map_err(|e| {
        if e.raw_os_error() == Some(740) {
            "The uninstaller requires administrator rights.".to_string()
        } else {
            format!("Could not start the uninstaller: {e}")
        }
    })?;
    if r.timed_out {
        return Err("The uninstaller is still running after the timeout.".into());
    }
    Ok(outcome(r.exit_code as i64, &[0], &[3010, 1641], "Uninstaller", ""))
}

fn remove_appx(full_name: &str) -> Result<ExecOutcome, String> {
    use windows::Management::Deployment::PackageManager;
    let pm = PackageManager::new().map_err(|e| e.message().to_string())?;
    let result = pm
        .RemovePackageAsync(&HSTRING::from(full_name))
        .and_then(|op| op.join())
        .map_err(|e| e.message().to_string())?;
    let hr = result.ExtendedErrorCode().map_err(|e| e.message().to_string())?;
    if hr.is_ok() {
        Ok(ExecOutcome { success: true, message: "Package removed".into(), ..Default::default() })
    } else {
        let text = result.ErrorText().map(|t| t.to_string()).unwrap_or_default();
        Err(format!("Package removal failed ({hr:?}): {text}"))
    }
}

fn run_dism(action: &str, arg: &str, name: &str) -> Result<ExecOutcome, String> {
    if !is_safe_identifier(name) || name.contains(' ') {
        return Err("invalid component name".into());
    }
    let (code, out) = run_tool(
        system32("dism.exe"),
        ["/online", "/english", action, &format!("/{arg}:{name}"), "/norestart", "/quiet"],
    )
    .map_err(|e| e.to_string())?;
    Ok(outcome(code as i64, &[0], &[3010], "DISM", &exec::last_line(&out)))
}

fn remove_driver(inf: &str) -> Result<ExecOutcome, String> {
    let lower = inf.to_ascii_lowercase();
    let valid = lower.starts_with("oem")
        && lower.ends_with(".inf")
        && lower[3..lower.len() - 4].chars().all(|c| c.is_ascii_digit())
        && lower.len() > 7;
    if !valid {
        return Err("invalid driver package name".into());
    }
    let (code, out) = run_tool(system32("pnputil.exe"), ["/delete-driver", inf, "/uninstall", "/force"])
        .map_err(|e| e.to_string())?;
    Ok(outcome(code as i64, &[0], &[3010], "pnputil", &exec::last_line(&out)))
}

fn tool_path(manager: &str, tool: Option<&str>) -> Result<PathBuf, String> {
    let home = env_path("USERPROFILE").unwrap_or_default();
    Ok(match manager {
        "choco" => env_path("ChocolateyInstall")
            .or_else(|| env_path("ProgramData").map(|p| p.join("chocolatey")))
            .map(|p| p.join(r"bin\choco.exe"))
            .unwrap_or_else(|| PathBuf::from("choco.exe")),
        "scoop" => {
            let root = env_path("SCOOP").unwrap_or_else(|| home.join("scoop"));
            root.join(r"shims\scoop.cmd")
        }
        "npm" => PathBuf::from("npm.cmd"),
        "pip" => {
            let python = PathBuf::from(tool.ok_or("no interpreter recorded for this package")?);
            let ok = python.is_file()
                && python.file_name().is_some_and(|f| f.to_string_lossy().eq_ignore_ascii_case("python.exe"));
            if !ok {
                return Err("the recorded Python interpreter is missing".into());
            }
            python
        }
        "cargo" => {
            let bin = env_path("CARGO_HOME").unwrap_or_else(|| home.join(".cargo")).join(r"bin\cargo.exe");
            if bin.is_file() { bin } else { PathBuf::from("cargo.exe") }
        }
        "rustup" => {
            let bin = env_path("CARGO_HOME").unwrap_or_else(|| home.join(".cargo")).join(r"bin\rustup.exe");
            if bin.is_file() { bin } else { PathBuf::from("rustup.exe") }
        }
        "dotnet-tool" => PathBuf::from("dotnet.exe"),
        other => return Err(format!("unsupported package manager {other}")),
    })
}

fn run_package_manager(manager: &str, name: &str, tool: Option<&str>) -> Result<ExecOutcome, String> {
    if !is_safe_package_name(name) {
        return Err("invalid package name".into());
    }
    let exe = tool_path(manager, tool)?;
    let args: Vec<&str> = match manager {
        "choco" => vec!["uninstall", name, "-y"],
        "scoop" if tool == Some("global") => vec!["uninstall", name, "-g"],
        "scoop" => vec!["uninstall", name],
        "npm" => vec!["uninstall", "-g", name],
        "pip" => vec!["-m", "pip", "uninstall", "-y", name],
        "cargo" => vec!["uninstall", name],
        "rustup" => vec!["toolchain", "uninstall", name],
        "dotnet-tool" => vec!["tool", "uninstall", "-g", name],
        _ => unreachable!("validated in tool_path"),
    };
    let (code, out) = run_tool(&exe, args).map_err(|e| format!("could not run {}: {e}", exe.display()))?;
    Ok(outcome(code as i64, &[0], &[], manager, &exec::last_line(&out)))
}

fn clean_dir(path: &str) -> Result<ExecOutcome, String> {
    let dir = Path::new(path);
    if !dir.is_dir() || deny::is_denied_path(&format!(r"{path}\x")) {
        return Err("folder is missing or protected".into());
    }
    let (mut removed, mut failed) = (0usize, 0usize);
    for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())?.flatten() {
        let p = entry.path();
        // remove_dir_all does not follow junctions or symlinks.
        let result = match entry.file_type() {
            Ok(t) if t.is_dir() && !t.is_symlink() => std::fs::remove_dir_all(&p),
            Ok(t) if t.is_dir() => std::fs::remove_dir(&p),
            _ => std::fs::remove_file(&p),
        };
        if result.is_ok() { removed += 1 } else { failed += 1 }
    }
    Ok(ExecOutcome {
        success: true,
        message: format!("Removed {removed} entries{}", if failed > 0 { format!(", {failed} in use were skipped") } else { String::new() }),
        ..Default::default()
    })
}

/// Runs one uninstall method. Recorded removals (startup, task, service, path) are handled by the
/// engine through the safety layer instead.
pub fn execute(item: &Item, options: &ExecOptions) -> Result<ExecOutcome, String> {
    if let Some(reason) = item.removal_block() {
        return Err(reason.to_string());
    }
    let method = item.uninstall.get(options.method).ok_or("unknown removal method")?;
    if matches!(method, UninstallMethod::Command { .. } | UninstallMethod::Msi { .. } | UninstallMethod::PackageManager { .. })
        && let Some(dir) = item.install_location.as_deref().filter(|d| !deny::is_denied_path(d))
    {
        for p in processes_in(dir) {
            let _ = terminate(p.pid);
        }
    }
    match method {
        UninstallMethod::Command { command, quiet } => run_command(command, *quiet, options.silent),
        UninstallMethod::Msi { product_code } => run_msi(product_code, options.silent),
        UninstallMethod::Appx { package_full_name } => remove_appx(package_full_name),
        UninstallMethod::Driver { inf } => remove_driver(inf),
        UninstallMethod::Feature { name } => run_dism("/disable-feature", "featurename", name),
        UninstallMethod::Capability { name } => run_dism("/remove-capability", "capabilityname", name),
        UninstallMethod::Update { package } => run_dism("/remove-package", "packagename", package),
        UninstallMethod::PackageManager { manager, name, tool } => run_package_manager(manager, name, tool.as_deref()),
        UninstallMethod::CleanDir { path } => clean_dir(path),
        UninstallMethod::Service { .. }
        | UninstallMethod::Task { .. }
        | UninstallMethod::RegistryValue { .. }
        | UninstallMethod::DeletePath { .. } => Err("recorded removals are executed by the engine".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_inno_uninstallers() {
        assert_eq!(silent_switch(r"C:\nope\unins000.exe"), Some("/VERYSILENT /SUPPRESSMSGBOXES /NORESTART"));
        assert_eq!(silent_switch(r"C:\nope\uninstall.exe"), None);
    }

    #[test]
    fn user_scope_commands_run_unelevated() {
        let mut item = Item::new(ItemKind::Win32, "x", "y");
        let cmd = UninstallMethod::Command { command: "x.exe".into(), quiet: false };
        assert!(!runs_unelevated(&item, &cmd));
        item.scope = Scope::User;
        assert!(runs_unelevated(&item, &cmd));
        assert!(!runs_unelevated(&item, &UninstallMethod::Msi { product_code: "{x}".into() }));
    }
}
