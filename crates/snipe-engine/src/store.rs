//! Secure storage root for transactions, backups and quarantine (`%ProgramData%\Snipe`).
//!
//! The folder is restricted to SYSTEM and Administrators: an attacker who could write a
//! transaction manifest could otherwise make "undo" restore arbitrary files as admin.

use snipe_collectors::util::{is_reparse_point, to_wide};
use std::ffi::c_void;
use std::io;
use std::path::PathBuf;
use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::CreateDirectoryW;
use windows::core::{PCWSTR, PWSTR};

const SDDL: &str = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
const TRUSTED_OWNERS: &[&str] = &["S-1-5-32-544", "S-1-5-18"];

fn owner_sid(path: &str) -> Option<String> {
    let wide = to_wide(path);
    // SAFETY: out-pointers are valid; the descriptor is freed with LocalFree.
    unsafe {
        let mut owner = PSID::default();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let err = GetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut sd,
        );
        if err != ERROR_SUCCESS {
            return None;
        }
        let mut text = PWSTR::null();
        let result = ConvertSidToStringSidW(owner, &mut text).ok().map(|_| {
            let s = text.to_string().unwrap_or_default();
            let _ = LocalFree(Some(HLOCAL(text.0 as *mut c_void)));
            s
        });
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        result
    }
}

fn create_secure_dir(path: &str) -> io::Result<()> {
    let sddl = to_wide(SDDL);
    let wide = to_wide(path);
    // SAFETY: the descriptor lives until LocalFree after CreateDirectoryW returns.
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), SDDL_REVISION_1, &mut sd, None)
            .map_err(io::Error::other)?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };
        let result = CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(&sa));
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        result.map_err(io::Error::other)
    }
}

/// Returns `%ProgramData%\Snipe`, creating it with a protected ACL. Requires elevation.
pub fn data_root() -> io::Result<PathBuf> {
    let pd = std::env::var("ProgramData").map_err(|_| io::Error::other("ProgramData not set"))?;
    let root = PathBuf::from(pd).join("Snipe");
    let root_str = root.to_string_lossy().into_owned();
    if let Ok(meta) = std::fs::symlink_metadata(&root) {
        let trusted = !is_reparse_point(&meta)
            && meta.is_dir()
            && owner_sid(&root_str).is_some_and(|o| TRUSTED_OWNERS.contains(&o.as_str()));
        if !trusted {
            // Someone else pre-created it: move it aside rather than trusting its contents.
            let stamp = crate::safety::now();
            std::fs::rename(&root, root.with_file_name(format!("Snipe.untrusted-{stamp}")))?;
        }
    }
    if !root.exists() {
        create_secure_dir(&root_str)?;
    }
    let txn = root.join("txn");
    std::fs::create_dir_all(&txn)?;
    Ok(root)
}

pub fn txn_root() -> io::Result<PathBuf> {
    Ok(data_root()?.join("txn"))
}
