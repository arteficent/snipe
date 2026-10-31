//! Running processes via a Toolhelp snapshot.

use crate::util::{account_from_psid, wide_to_string};
use snipe_core::{CollectResult, Collector, Item, ItemKind, Protection, paths};
use std::ffi::c_void;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    IsProcessCritical, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};
use windows::core::{BOOL, PWSTR};

pub struct ProcessesCollector;

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: handle is owned and closed exactly once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

impl Collector for ProcessesCollector {
    fn id(&self) -> &'static str {
        "processes"
    }

    fn label(&self) -> &'static str {
        "Running processes"
    }

    fn collect(&self) -> CollectResult<Vec<Item>> {
        let mut items = Vec::new();
        // SAFETY: standard Toolhelp enumeration with a correctly sized entry struct.
        unsafe {
            let snap = OwnedHandle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?);
            let mut entry = PROCESSENTRY32W {
                dwSize: size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };
            let mut ok = Process32FirstW(snap.0, &mut entry).is_ok();
            while ok {
                items.push(read_process(&entry));
                ok = Process32NextW(snap.0, &mut entry).is_ok();
            }
        }
        Ok(items)
    }
}

fn read_process(entry: &PROCESSENTRY32W) -> Item {
    let pid = entry.th32ProcessID;
    let exe_name = wide_to_string(&entry.szExeFile);
    let mut item = Item::new(ItemKind::Process, exe_name, format!(r"Process\{pid}"));
    item.detail("PID", pid.to_string());
    item.detail("Parent PID", entry.th32ParentProcessID.to_string());
    item.detail("Threads", entry.cntThreads.to_string());

    let (image, critical, user) = query_image(pid);
    item.user = user;
    if let Some(path) = &image {
        item.detail("Image path", path.clone());
        item.install_location = paths::parent_dir(path);
        item.executable = Some(path.clone());
    }

    if pid == 0 || pid == 4 || critical {
        item.protection = Protection::Locked;
        item.hidden = true;
    } else {
        match &image {
            Some(path) if !paths::is_windows_path(path) => {}
            Some(_) => {
                item.protection = Protection::System;
                item.hidden = true;
            }
            // Access denied: protected or other-session process.
            None => {
                item.protection = Protection::Locked;
                item.hidden = true;
            }
        }
    }
    if critical {
        item.detail("Critical", "yes");
    }
    item
}

fn query_image(pid: u32) -> (Option<String>, bool, Option<String>) {
    if pid == 0 || pid == 4 {
        return (None, false, Some(r"NT AUTHORITY\SYSTEM".into()));
    }
    // SAFETY: handles are owned and closed by OwnedHandle; buffer lengths are passed explicitly.
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return (None, false, None);
        };
        let handle = OwnedHandle(handle);
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let image = QueryFullProcessImageNameW(handle.0, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len)
            .ok()
            .map(|_| String::from_utf16_lossy(&buf[..len as usize]));
        let mut critical = BOOL(0);
        let critical = IsProcessCritical(handle.0, &mut critical).is_ok() && critical.as_bool();

        let mut user = None;
        let mut token = HANDLE::default();
        if OpenProcessToken(handle.0, TOKEN_QUERY, &mut token).is_ok() {
            let token = OwnedHandle(token);
            // u64 storage keeps TOKEN_USER pointer-aligned.
            let mut storage = [0u64; 64];
            let mut needed = 0u32;
            if GetTokenInformation(
                token.0,
                TokenUser,
                Some(storage.as_mut_ptr().cast::<c_void>()),
                size_of_val(&storage) as u32,
                &mut needed,
            )
            .is_ok()
            {
                let token_user = &*storage.as_ptr().cast::<TOKEN_USER>();
                user = account_from_psid(token_user.User.Sid);
            }
        }
        (image, critical, user)
    }
}
