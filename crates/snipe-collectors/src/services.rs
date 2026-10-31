//! Win32 services via the Service Control Manager.

use crate::util::pwstr_to_string;
use snipe_core::{CollectResult, Collector, Item, ItemKind, Protection, UninstallMethod, paths};
use windows::Win32::Foundation::ERROR_MORE_DATA;
use windows::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW,
    QUERY_SERVICE_CONFIGW, QueryServiceConfigW, SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_AUTO_START, SERVICE_BOOT_START, SERVICE_DEMAND_START,
    SERVICE_DISABLED, SERVICE_PAUSED, SERVICE_QUERY_CONFIG, SERVICE_RUNNING, SERVICE_STATE_ALL,
    SERVICE_STOPPED, SERVICE_SYSTEM_START, SERVICE_WIN32,
};
use windows::core::PCWSTR;

pub struct ServicesCollector;

struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: handle was returned by OpenSCManagerW/OpenServiceW and is closed once.
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

impl Collector for ServicesCollector {
    fn id(&self) -> &'static str {
        "services"
    }

    fn label(&self) -> &'static str {
        "Services"
    }

    fn collect(&self) -> CollectResult<Vec<Item>> {
        // SAFETY: plain Win32 calls; buffers are sized and aligned for the returned structs.
        unsafe {
            let scm = ScHandle(OpenSCManagerW(
                PCWSTR::null(),
                PCWSTR::null(),
                SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
            )?);

            let mut items = Vec::new();
            let mut resume: u32 = 0;
            // u64 storage keeps the struct array correctly aligned.
            let mut storage = vec![0u64; 256 * 1024 / 8];
            loop {
                let bytes = std::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), storage.len() * 8);
                let mut needed = 0u32;
                let mut returned = 0u32;
                let res = EnumServicesStatusExW(
                    scm.0,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32,
                    SERVICE_STATE_ALL,
                    Some(bytes),
                    &mut needed,
                    &mut returned,
                    Some(&mut resume),
                    PCWSTR::null(),
                );
                let more = match &res {
                    Ok(()) => false,
                    Err(e) if e.code() == ERROR_MORE_DATA.to_hresult() => true,
                    Err(e) => return Err(e.clone().into()),
                };
                let entries = std::slice::from_raw_parts(
                    storage.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),
                    returned as usize,
                );
                for entry in entries {
                    items.push(read_service(&scm, entry));
                }
                if !more {
                    break;
                }
                if returned == 0 {
                    // Buffer too small for even one entry: grow it.
                    storage.resize((needed as usize).div_ceil(8) + storage.len(), 0);
                }
            }
            Ok(items)
        }
    }
}

unsafe fn read_service(scm: &ScHandle, entry: &ENUM_SERVICE_STATUS_PROCESSW) -> Item {
    // SAFETY: strings in the entry point into the enumeration buffer, which outlives this call.
    let (name, display) = unsafe { (pwstr_to_string(entry.lpServiceName.0), pwstr_to_string(entry.lpDisplayName.0)) };
    let status = &entry.ServiceStatusProcess;

    let mut item = Item::new(
        ItemKind::Service,
        if display.is_empty() { name.clone() } else { display },
        format!(r"Service\{name}"),
    );

    let state = match status.dwCurrentState {
        SERVICE_RUNNING => "Running",
        SERVICE_STOPPED => "Stopped",
        SERVICE_PAUSED => "Paused",
        _ => "Pending",
    };
    item.detail("Service name", name.clone());
    item.detail("State", state);
    if status.dwProcessId != 0 {
        item.detail("PID", status.dwProcessId.to_string());
    }

    // SAFETY: handles are valid for the lifetime of `scm`.
    let config = unsafe { query_config(scm, &name) };
    if let Some((binary, start, account)) = &config {
        item.detail("Start type", *start);
        item.detail("Account", account.clone());
        item.detail("Image path", binary.clone());
        item.user = Some(account.clone()).filter(|a| !a.is_empty());
    }

    let exe = config.as_ref().and_then(|(binary, _, _)| paths::exe_from_command(binary));
    // svchost-hosted services run a DLL; that DLL is what identifies (and may disguise) them.
    let service_dll = exe
        .as_deref()
        .filter(|e| e.to_ascii_lowercase().ends_with(r"\svchost.exe"))
        .and_then(|_| {
            winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
                .open_subkey(format!(r"SYSTEM\CurrentControlSet\Services\{name}\Parameters"))
                .ok()?
                .get_value::<String, _>("ServiceDll")
                .ok()
        })
        .map(|d| paths::expand(&d));
    if let Some(dll) = &service_dll {
        item.detail("Service DLL", dll.clone());
    }
    let executable = service_dll.or(exe);
    item.executable = executable.clone();
    let in_windows = executable.as_deref().is_none_or(paths::is_windows_path);
    if in_windows {
        item.protection = Protection::Locked;
        item.hidden = true;
    } else {
        item.install_location = executable.as_deref().and_then(paths::parent_dir);
        item.uninstall.push(UninstallMethod::Service { name });
    }
    item
}

unsafe fn query_config(scm: &ScHandle, name: &str) -> Option<(String, &'static str, String)> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is NUL-terminated; buffers are sized from the first call.
    unsafe {
        let svc = ScHandle(OpenServiceW(scm.0, PCWSTR(wide.as_ptr()), SERVICE_QUERY_CONFIG).ok()?);
        let mut needed = 0u32;
        let _ = QueryServiceConfigW(svc.0, None, 0, &mut needed);
        if needed == 0 {
            return None;
        }
        let mut storage = vec![0u64; (needed as usize).div_ceil(8)];
        let cfg = storage.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        QueryServiceConfigW(svc.0, Some(cfg), needed, &mut needed).ok()?;
        let cfg = &*cfg;
        let start = match cfg.dwStartType {
            SERVICE_AUTO_START => "Automatic",
            SERVICE_DEMAND_START => "Manual",
            SERVICE_DISABLED => "Disabled",
            SERVICE_BOOT_START => "Boot",
            SERVICE_SYSTEM_START => "System",
            _ => "Unknown",
        };
        Some((
            paths::expand(&pwstr_to_string(cfg.lpBinaryPathName.0)),
            start,
            pwstr_to_string(cfg.lpServiceStartName.0),
        ))
    }
}
