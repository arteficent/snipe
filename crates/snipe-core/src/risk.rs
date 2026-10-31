//! Heuristic risk assessment for executables. This is not an antivirus: it flags software that
//! lacks a trusted signature or behaves like common malware persistence so a human can review it.

use crate::{ItemKind, paths};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SignatureStatus {
    /// Valid signature chaining to a trusted root (embedded or Windows catalog).
    Trusted,
    Unsigned,
    /// Signed, but by a self-signed or otherwise untrusted certificate.
    Untrusted,
    /// Signature broken, revoked or explicitly distrusted.
    Invalid,
    /// Certificate expired and the signature has no timestamp.
    Expired,
    /// The file could not be read.
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    pub status: SignatureStatus,
    pub signer: Option<String>,
}

pub const SUSPICIOUS: u8 = 70;
pub const UNTRUSTED: u8 = 40;

/// Windows system binaries that malware commonly impersonates.
const SYSTEM_NAMES: &[&str] = &[
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "explorer.exe",
    "spoolsv.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe", "rundll32.exe", "wininit.exe", "lsm.exe",
    "taskmgr.exe", "regsvr32.exe", "ctfmon.exe", "sihost.exe", "dwm.exe", "fontdrvhost.exe", "searchindexer.exe",
];

const DOC_EXTENSIONS: &[&str] = &[".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".zip", ".mp4"];
const EXEC_EXTENSIONS: &[&str] = &[".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".js", ".ps1"];

pub struct RiskInput<'a> {
    pub kind: ItemKind,
    pub executable: Option<&'a str>,
    pub signature: Option<&'a Signature>,
    /// Command line for autostart entries (startup, task, service).
    pub command: Option<&'a str>,
    pub file_hidden: bool,
}

fn is_autostart(kind: ItemKind) -> bool {
    matches!(kind, ItemKind::Startup | ItemKind::Task | ItemKind::Service)
}

/// Returns a 0–100 score and the reasons behind it.
pub fn assess(input: &RiskInput<'_>) -> (u8, Vec<String>) {
    let mut score: u32 = 0;
    let mut reasons = Vec::new();
    let mut add = |points: u32, reason: &str| {
        score += points;
        reasons.push(reason.to_string());
    };

    let status = input.signature.map(|s| s.status);
    let untrusted_binary = matches!(
        status,
        Some(SignatureStatus::Unsigned | SignatureStatus::Untrusted | SignatureStatus::Invalid)
    );
    match status {
        Some(SignatureStatus::Invalid) => add(80, "signature is broken, revoked or distrusted (file may be tampered with)"),
        Some(SignatureStatus::Untrusted) => add(50, "signed with a self-signed or untrusted certificate"),
        Some(SignatureStatus::Unsigned) => add(35, "not digitally signed"),
        Some(SignatureStatus::Expired) => add(10, "signing certificate expired and is not timestamped"),
        _ => {}
    }

    if let Some(exe) = input.executable {
        let lower = exe.to_ascii_lowercase();
        let file = lower.rsplit('\\').next().unwrap_or(&lower);
        let in_windows = paths::is_windows_path(exe);

        if SYSTEM_NAMES.contains(&file) && !in_windows {
            let trusted = status == Some(SignatureStatus::Trusted);
            add(if trusted { 20 } else { 60 }, "uses the name of a Windows system file outside the Windows folder");
        }
        if let Some(stem) = EXEC_EXTENSIONS.iter().find_map(|e| file.strip_suffix(e))
            && DOC_EXTENSIONS.iter().any(|d| stem.ends_with(d))
        {
            add(40, "disguised with a double file extension");
        }
        if status != Some(SignatureStatus::Trusted) {
            if lower.contains(r"\appdata\local\temp\") || lower.contains(r"\windows\temp\") {
                add(30, "runs from a temporary folder");
            } else if lower.contains(r"\appdata\")
                || lower.contains(r"\users\public\")
                || lower.contains(r"\downloads\")
                || lower.contains(r"\desktop\")
            {
                add(15, "runs from a user-writable folder");
            }
        }
        if input.file_hidden && !in_windows {
            add(15, "the file is hidden");
        }
        if is_autostart(input.kind) && untrusted_binary {
            add(15, "starts automatically");
        }
        if is_autostart(input.kind) && [".scr", ".pif", ".com"].iter().any(|e| file.ends_with(e)) {
            add(20, "autostarts an unusual executable type");
        }
    }

    if let Some(cmd) = input.command {
        let c = cmd.to_ascii_lowercase();
        if c.contains(" -enc ")
            || c.contains("-encodedcommand")
            || c.contains("frombase64string")
            || (c.contains(" -e ") && c.contains("powershell"))
        {
            add(40, "runs an encoded PowerShell command");
        }
        let launcher = ["powershell", "pwsh", "mshta", "rundll32", "regsvr32", "wscript", "cscript", "bitsadmin", "certutil", "curl"]
            .iter()
            .any(|l| c.contains(l));
        if launcher && (c.contains("http://") || c.contains("https://")) {
            add(35, "downloads or runs remote content at startup");
        }
        if c.contains("-windowstyle hidden") || c.contains("-w hidden") || (c.contains("-nop ") && c.contains("hidden")) {
            add(15, "hides its window");
        }
    }

    (score.min(100) as u8, reasons)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(status: SignatureStatus) -> Signature {
        Signature { status, signer: None }
    }

    #[test]
    fn trusted_programs_score_zero() {
        let s = sig(SignatureStatus::Trusted);
        let (score, reasons) = assess(&RiskInput {
            kind: ItemKind::Process,
            executable: Some(r"C:\Users\bob\AppData\Local\Programs\App\app.exe"),
            signature: Some(&s),
            command: None,
            file_hidden: false,
        });
        assert_eq!(score, 0, "{reasons:?}");
    }

    #[test]
    fn flags_unsigned_masquerading_autostart() {
        let s = sig(SignatureStatus::Unsigned);
        let (score, _) = assess(&RiskInput {
            kind: ItemKind::Startup,
            executable: Some(r"C:\Users\bob\AppData\Roaming\svchost.exe"),
            signature: Some(&s),
            command: None,
            file_hidden: true,
        });
        assert!(score >= SUSPICIOUS);
    }

    #[test]
    fn flags_encoded_powershell_and_double_extensions() {
        let s = sig(SignatureStatus::Trusted);
        let (score, _) = assess(&RiskInput {
            kind: ItemKind::Task,
            executable: Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            signature: Some(&s),
            command: Some("powershell.exe -nop -w hidden -enc SQBFAFgA"),
            file_hidden: false,
        });
        assert!(score >= UNTRUSTED);
        let u = sig(SignatureStatus::Unsigned);
        let (score, reasons) = assess(&RiskInput {
            kind: ItemKind::Process,
            executable: Some(r"C:\Users\bob\Downloads\invoice.pdf.exe"),
            signature: Some(&u),
            command: None,
            file_hidden: false,
        });
        assert!(score >= SUSPICIOUS, "{reasons:?}");
    }
}
