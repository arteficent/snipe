//! Authenticode verification (embedded signatures and Windows catalogs) and risk scoring.

use crate::util::{to_wide, wide_to_string};
use snipe_core::risk::{RiskInput, assess as assess_risk};
use snipe_core::{Item, Signature, SignatureStatus};
use std::collections::HashMap;
use std::ffi::c_void;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::Security::Cryptography::Catalog::{
    CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash,
    CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
};
use windows::Win32::Security::Cryptography::{CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WinVerifyTrust,
};
use windows::core::{PCWSTR, w};

const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;
const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = 0x800B_0003;
const TRUST_E_PROVIDER_UNKNOWN: u32 = 0x800B_0001;
const CERT_E_EXPIRED: u32 = 0x800B_0101;
const CERT_E_UNTRUSTEDROOT: u32 = 0x800B_0109;
const CERT_E_CHAINING: u32 = 0x800B_010A;
const CERT_E_UNTRUSTEDTESTROOT: u32 = 0x800B_010D;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;

/// Runs WinVerifyTrust on prepared data and returns (result, signer display name).
unsafe fn verify(data: &mut WINTRUST_DATA) -> (u32, Option<String>) {
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data` is fully initialised by the caller; state is closed below.
    unsafe {
        let result = WinVerifyTrust(HWND(-1isize as *mut c_void), &mut action, data as *mut _ as *mut c_void) as u32;
        let mut signer = None;
        let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
        if !prov.is_null() {
            let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
            if !sgnr.is_null() && (*sgnr).csCertChain > 0 && !(*sgnr).pasCertChain.is_null() {
                let cert = (*(*sgnr).pasCertChain).pCert;
                if !cert.is_null() {
                    let mut buf = [0u16; 256];
                    let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut buf));
                    if n > 1 {
                        signer = Some(wide_to_string(&buf));
                    }
                }
            }
        }
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(HWND(-1isize as *mut c_void), &mut action, data as *mut _ as *mut c_void);
        (result, signer)
    }
}

fn base_data() -> WINTRUST_DATA {
    WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        // Offline and fast: no revocation network calls.
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    }
}

fn verify_embedded(path_w: &[u16]) -> (u32, Option<String>) {
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(path_w.as_ptr()),
        ..Default::default()
    };
    let mut data = base_data();
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous = WINTRUST_DATA_0 { pFile: &mut file };
    // SAFETY: `file` and `path_w` outlive the call.
    unsafe { verify(&mut data) }
}

/// Windows ships most of its binaries catalog-signed rather than with embedded signatures.
fn verify_catalog(path: &str, path_w: &[u16]) -> Option<(u32, Option<String>)> {
    let file = std::fs::File::open(path).ok()?;
    let handle = HANDLE(file.as_raw_handle());
    for algorithm in [w!("SHA256"), PCWSTR::null()] {
        // SAFETY: every acquired context and catalog handle is released before returning.
        unsafe {
            let mut admin = 0isize;
            if CryptCATAdminAcquireContext2(&mut admin, None, algorithm, None, None).is_err() {
                continue;
            }
            let mut size = 0u32;
            let _ = CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut size, None, None);
            let mut hash = vec![0u8; size as usize];
            let result = if size > 0
                && CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut size, Some(hash.as_mut_ptr()), None).is_ok()
            {
                let cat = CryptCATAdminEnumCatalogFromHash(admin, &hash, None, None);
                if cat != 0 {
                    let mut info = CATALOG_INFO { cbStruct: size_of::<CATALOG_INFO>() as u32, ..Default::default() };
                    let r = if CryptCATCatalogInfoFromContext(cat, &mut info, 0).is_ok() {
                        let tag: String = hash.iter().map(|b| format!("{b:02X}")).collect();
                        let tag_w = to_wide(&tag);
                        let mut catalog = WINTRUST_CATALOG_INFO {
                            cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
                            pcwszCatalogFilePath: PCWSTR(info.wszCatalogFile.as_ptr()),
                            pcwszMemberTag: PCWSTR(tag_w.as_ptr()),
                            pcwszMemberFilePath: PCWSTR(path_w.as_ptr()),
                            hMemberFile: handle,
                            pbCalculatedFileHash: hash.as_mut_ptr(),
                            cbCalculatedFileHash: size,
                            hCatAdmin: admin,
                            ..Default::default()
                        };
                        let mut data = base_data();
                        data.dwUnionChoice = WTD_CHOICE_CATALOG;
                        data.Anonymous = WINTRUST_DATA_0 { pCatalog: &mut catalog };
                        Some(verify(&mut data))
                    } else {
                        None
                    };
                    let _ = CryptCATAdminReleaseCatalogContext(admin, cat, 0);
                    r
                } else {
                    None
                }
            } else {
                None
            };
            let _ = CryptCATAdminReleaseContext(admin, 0);
            if result.is_some() {
                return result;
            }
        }
    }
    None
}

fn classify(code: u32) -> SignatureStatus {
    match code {
        0 => SignatureStatus::Trusted,
        TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN => SignatureStatus::Unsigned,
        CERT_E_EXPIRED => SignatureStatus::Expired,
        CERT_E_UNTRUSTEDROOT | CERT_E_CHAINING | CERT_E_UNTRUSTEDTESTROOT => SignatureStatus::Untrusted,
        // Bad digest, revoked, explicitly distrusted, malformed…
        _ => SignatureStatus::Invalid,
    }
}

/// Verifies the Authenticode signature of a file (embedded first, then Windows catalogs).
pub fn check_file(path: &str) -> Signature {
    if !std::path::Path::new(path).is_file() {
        return Signature { status: SignatureStatus::Unknown, signer: None };
    }
    let path_w = to_wide(path);
    let (code, signer) = verify_embedded(&path_w);
    let status = classify(code);
    if status == SignatureStatus::Unsigned
        && let Some((cat_code, cat_signer)) = verify_catalog(path, &path_w)
    {
        return Signature { status: classify(cat_code), signer: cat_signer };
    }
    Signature { status, signer }
}

type CacheKey = (String, u64, u64);

/// Signatures cached by path, size and modification time for the lifetime of the process.
fn cached_check(path: &str) -> Signature {
    static CACHE: OnceLock<Mutex<HashMap<CacheKey, Signature>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    let meta = std::fs::metadata(path).ok();
    let key = (
        path.to_ascii_lowercase(),
        meta.as_ref().map(|m| m.len()).unwrap_or(0),
        meta.as_ref().map(|m| m.last_write_time()).unwrap_or(0),
    );
    if let Some(hit) = cache.lock().ok().and_then(|c| c.get(&key).cloned()) {
        return hit;
    }
    let sig = check_file(path);
    if let Ok(mut c) = cache.lock() {
        c.insert(key, sig.clone());
    }
    sig
}

fn command_of(item: &Item) -> Option<&str> {
    item.details
        .iter()
        .find(|(k, _)| k == "Command" || k == "Action" || k == "Image path")
        .map(|(_, v)| v.as_str())
}

/// Verifies signatures (in parallel, deduplicated) and computes the risk score of every item.
pub fn assess(items: &mut [Item]) {
    for item in items.iter_mut() {
        if let Some(exe) = &mut item.executable {
            *exe = exe.trim().trim_matches('"').replace('/', "\\");
        }
    }
    let mut paths: Vec<String> = items
        .iter()
        .filter(|i| i.signature.is_none())
        .filter_map(|i| i.executable.clone())
        .collect();
    paths.sort_by_key(|p| p.to_ascii_lowercase());
    paths.dedup_by_key(|p| p.to_ascii_lowercase());

    let results: Mutex<HashMap<String, Signature>> = Mutex::new(HashMap::new());
    let next = AtomicUsize::new(0);
    let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(2, 8);
    std::thread::scope(|s| {
        for _ in 0..workers.min(paths.len()) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(path) = paths.get(i) else { break };
                    let sig = cached_check(path);
                    if let Ok(mut r) = results.lock() {
                        r.insert(path.to_ascii_lowercase(), sig);
                    }
                }
            });
        }
    });
    let results = results.into_inner().unwrap_or_default();

    for item in items.iter_mut() {
        if item.signature.is_none()
            && let Some(exe) = &item.executable
        {
            item.signature = results.get(&exe.to_ascii_lowercase()).cloned();
        }
        if item.signature.is_none() {
            continue;
        }
        let hidden = item
            .executable
            .as_deref()
            .and_then(|p| std::fs::metadata(p).ok())
            .is_some_and(|m| m.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0);
        let (score, reasons) = assess_risk(&RiskInput {
            kind: item.kind,
            executable: item.executable.as_deref(),
            signature: item.signature.as_ref(),
            command: command_of(item),
            file_hidden: hidden,
        });
        item.risk = score;
        item.risk_reasons = reasons;
        if let Some(sig) = item.signature.clone() {
            let label = match sig.status {
                SignatureStatus::Trusted => "Trusted",
                SignatureStatus::Unsigned => "Not signed",
                SignatureStatus::Untrusted => "Untrusted / self-signed",
                SignatureStatus::Invalid => "Invalid",
                SignatureStatus::Expired => "Expired",
                SignatureStatus::Unknown => "Could not verify",
            };
            item.detail("Signature", label);
            if let Some(signer) = &sig.signer {
                item.detail("Signed by", signer.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_windows_binaries() {
        // cmd.exe exists on every edition (including CI runners) and is catalog-signed.
        let cmd = crate::util::system32("cmd.exe");
        let sig = check_file(&cmd.to_string_lossy());
        assert_eq!(sig.status, SignatureStatus::Trusted, "{sig:?}");
        assert!(sig.signer.unwrap_or_default().contains("Microsoft"));
    }

    #[test]
    fn missing_files_are_unknown() {
        assert_eq!(check_file(r"C:\definitely\missing.exe").status, SignatureStatus::Unknown);
    }
}
