//! Evidence that a file is owned by Windows itself, used to keep the `Locked`
//! protection level honest: an item is Windows-owned only when there is positive
//! proof, never because of its location alone. A third-party file dropped into a
//! Windows folder (for example a trojan in `System32`) fails every check here and
//! stays removable.

use crate::trust;
use crate::util::to_wide;
use snipe_core::SignatureStatus;
use std::ffi::c_void;
use windows::Win32::Foundation::{HANDLE, LocalFree};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
use windows::Win32::System::ApplicationInstallationAndServicing::SfcIsFileProtected;
use windows::core::{PCWSTR, PWSTR};

/// The well-known SID of `NT SERVICE\TrustedInstaller`.
const TRUSTED_INSTALLER_SID: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

/// True when `path` is proven to belong to Windows by any of three independent signals:
/// Windows File Protection, a `TrustedInstaller` owner, or a Microsoft Windows signature.
pub fn is_windows_owned(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    is_wrp_protected(path) || owner_is_trusted_installer(path) || signed_by_windows(path)
}

/// Windows Resource Protection: the file is part of a protected OS resource.
fn is_wrp_protected(path: &str) -> bool {
    let wide = to_wide(path);
    // SAFETY: a NUL-terminated path is passed; the call reads it and returns a BOOL.
    unsafe { SfcIsFileProtected(HANDLE::default(), PCWSTR(wide.as_ptr())).as_bool() }
}

/// The NTFS owner of the file is `TrustedInstaller`.
fn owner_is_trusted_installer(path: &str) -> bool {
    let wide = to_wide(path);
    let mut owner = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the path is NUL-terminated; `owner` points into `sd`, which is freed below.
    unsafe {
        let status = GetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut sd,
        );
        if status.is_err() || owner.is_invalid() {
            if !sd.0.is_null() {
                let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(sd.0)));
            }
            return false;
        }
        let mut sid_str = PWSTR::null();
        let matched = ConvertSidToStringSidW(owner, &mut sid_str).is_ok()
            && !sid_str.is_null()
            && sid_str.to_string().map(|s| s.eq_ignore_ascii_case(TRUSTED_INSTALLER_SID)).unwrap_or(false);
        if !sid_str.is_null() {
            let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(sid_str.0 as *mut c_void)));
        }
        if !sd.0.is_null() {
            let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(sd.0)));
        }
        matched
    }
}

/// The file carries a trusted Microsoft Windows signature (embedded or catalog).
fn signed_by_windows(path: &str) -> bool {
    let sig = trust::check_file(path);
    sig.status == SignatureStatus::Trusted
        && sig.signer.as_deref().is_some_and(|s| {
            let s = s.to_ascii_lowercase();
            s.contains("microsoft windows")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_path_is_not_owned() {
        assert!(!is_windows_owned(""));
    }

    #[test]
    fn a_user_file_is_not_windows_owned() {
        // This test file is not in System32, not WRP-protected and not Windows-signed.
        assert!(!is_windows_owned(file!()));
    }
}
