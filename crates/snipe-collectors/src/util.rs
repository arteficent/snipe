use std::collections::HashMap;
use std::ffi::c_void;
use std::os::windows::fs::MetadataExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, PSID, SID_NAME_USE, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{PCWSTR, PWSTR};
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// True when the current process token is elevated (running as administrator).
pub fn is_elevated() -> bool {
    static ELEVATED: OnceLock<bool> = OnceLock::new();
    *ELEVATED.get_or_init(|| {
        // SAFETY: token handle is closed below; buffer matches TOKEN_ELEVATION.
        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut c_void),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            )
            .is_ok();
            let _ = CloseHandle(token);
            ok && elevation.TokenIsElevated != 0
        }
    })
}

/// Resolves a SID to `DOMAIN\name`.
///
/// # Safety
/// `sid` must point to a valid SID.
pub unsafe fn account_from_psid(sid: PSID) -> Option<String> {
    let mut name = [0u16; 256];
    let mut name_len = name.len() as u32;
    let mut domain = [0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut sid_use = SID_NAME_USE::default();
    // SAFETY: buffers and lengths match.
    unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut sid_use,
        )
        .ok()?;
    }
    let name = wide_to_string(&name);
    let domain = wide_to_string(&domain);
    Some(if domain.is_empty() { name } else { format!(r"{domain}\{name}") })
}

/// Resolves a string SID (`S-1-5-21-…`) to an account name, cached.
pub fn account_from_sid(sid: &str) -> Option<String> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(hit) = cache.lock().ok()?.get(sid) {
        return hit.clone();
    }
    let wide = to_wide(sid);
    // SAFETY: the SID allocated by ConvertStringSidToSidW is freed with LocalFree.
    let resolved = unsafe {
        let mut psid = PSID::default();
        if ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut psid).is_ok() {
            let name = account_from_psid(psid);
            let _ = LocalFree(Some(HLOCAL(psid.0)));
            name
        } else {
            None
        }
    };
    cache.lock().ok()?.insert(sid.to_string(), resolved.clone());
    resolved
}

pub fn current_user() -> Option<String> {
    let user = std::env::var("USERNAME").ok()?;
    Some(match std::env::var("USERDOMAIN") {
        Ok(domain) => format!(r"{domain}\{user}"),
        Err(_) => user,
    })
}

fn is_user_sid(sid: &str) -> bool {
    (sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-")) && !sid.ends_with("_Classes")
}

/// SIDs of user hives currently loaded under HKEY_USERS.
pub fn loaded_user_sids() -> Vec<String> {
    RegKey::predef(HKEY_USERS)
        .enum_keys()
        .flatten()
        .filter(|s| is_user_sid(s))
        .collect()
}

/// (SID, profile folder) for every local user profile.
pub fn profiles() -> Vec<(String, PathBuf)> {
    let Ok(list) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList", KEY_READ)
    else {
        return Vec::new();
    };
    list.enum_keys()
        .flatten()
        .filter(|s| is_user_sid(s))
        .filter_map(|sid| {
            let key = list.open_subkey_with_flags(&sid, KEY_READ).ok()?;
            let path = reg_str(&key, "ProfileImagePath")?;
            let path = PathBuf::from(snipe_core::paths::expand(&path));
            path.is_dir().then_some((sid, path))
        })
        .collect()
}

/// A command that never flashes a console window.
pub fn hidden_command(exe: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut cmd = Command::new(exe);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

pub fn system32(file: &str) -> PathBuf {
    Path::new(snipe_core::paths::windows_dir()).join("System32").join(file)
}

pub fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Total size of a folder, without following junctions or symlinks.
pub fn dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if is_reparse_point(&meta) {
                continue;
            }
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                total += meta.len();
            }
        }
    }
    total
}

/// Reads a text file that may be UTF-16LE (with BOM), UTF-8 or ANSI.
pub fn read_text(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        return Some(String::from_utf16_lossy(&units));
    }
    let rest = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&bytes);
    Some(String::from_utf8_lossy(rest).into_owned())
}

pub fn env_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(PathBuf::from).filter(|p| !p.as_os_str().is_empty())
}

/// Reads a string value, returning `None` for missing or blank values.
pub fn reg_str(key: &RegKey, name: &str) -> Option<String> {
    key.get_value::<String, _>(name)
        .ok()
        .map(|s| s.trim().trim_matches('\0').to_string())
        .filter(|s| !s.is_empty())
}

pub fn reg_u32(key: &RegKey, name: &str) -> Option<u32> {
    key.get_value::<u32, _>(name).ok()
}

pub fn wide_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// Reads a UTF-16 C string from a raw pointer (used for Win32 struct fields).
///
/// # Safety
/// `ptr` must be null or point to a valid NUL-terminated UTF-16 string.
pub unsafe fn pwstr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: caller guarantees NUL termination.
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}
