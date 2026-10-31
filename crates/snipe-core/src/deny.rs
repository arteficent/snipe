//! Hard deny-list. Anything matched here is never deleted, whatever the scoring says.

use crate::paths::{self, windows_dir};

fn norm(path: &str) -> String {
    let mut p = path.trim().trim_matches('"').replace('/', "\\");
    for prefix in [r"\\?\", r"\??\"] {
        if let Some(rest) = p.strip_prefix(prefix) {
            p = rest.to_string();
        }
    }
    while p.ends_with('\\') {
        p.pop();
    }
    p.to_ascii_lowercase()
}

fn env_dir(var: &str, fallback: &str) -> String {
    norm(&std::env::var(var).unwrap_or_else(|_| fallback.to_string()))
}

fn system_drive() -> String {
    env_dir("SystemDrive", "C:")
}

/// Folders whose whole subtree is off-limits.
fn denied_trees() -> Vec<String> {
    let sd = system_drive();
    let pf = env_dir("ProgramFiles", r"C:\Program Files");
    let pd = env_dir("ProgramData", r"C:\ProgramData");
    vec![
        norm(windows_dir()),
        format!(r"{pf}\windowsapps"),
        format!(r"{pf}\windows defender"),
        format!(r"{pf}\windows defender advanced threat protection"),
        format!(r"{pd}\microsoft\windows defender"),
        format!(r"{pd}\snipe"),
        format!(r"{sd}\system volume information"),
        format!(r"{sd}\$recycle.bin"),
        format!(r"{sd}\recovery"),
        format!(r"{sd}\boot"),
    ]
}

/// Folders that may contain removable things but must never be removed themselves.
fn denied_exact() -> Vec<String> {
    let sd = system_drive();
    let pf = env_dir("ProgramFiles", r"C:\Program Files");
    let pf86 = env_dir("ProgramFiles(x86)", r"C:\Program Files (x86)");
    let pd = env_dir("ProgramData", r"C:\ProgramData");
    let mut v = vec![sd.clone(), format!(r"{sd}\users"), format!(r"{sd}\program files")];
    for root in [&pf, &pf86] {
        for sub in [
            "",
            r"\common files",
            r"\common files\microsoft shared",
            r"\microsoft",
            r"\dotnet",
            r"\windowspowershell",
            r"\windowspowershell\modules",
            r"\powershell",
            r"\powershell\modules",
            r"\internet explorer",
            r"\microsoft visual studio",
            r"\windows kits",
            r"\reference assemblies",
            r"\msbuild",
        ] {
            v.push(format!("{root}{sub}"));
        }
    }
    for sub in [
        "",
        r"\microsoft",
        r"\microsoft\windows",
        r"\microsoft\windows\start menu",
        r"\microsoft\windows\start menu\programs",
        r"\microsoft\windows\start menu\programs\startup",
        r"\package cache",
        r"\chocolatey",
        r"\chocolatey\lib",
    ] {
        v.push(format!("{pd}{sub}"));
    }
    v
}

/// Structural folders inside every user profile (relative to `Users\<name>`).
const PROFILE_STRUCTURE: &[&str] = &[
    "",
    "appdata",
    r"appdata\roaming",
    r"appdata\local",
    r"appdata\locallow",
    r"appdata\local\programs",
    r"appdata\local\packages",
    r"appdata\local\temp",
    r"appdata\local\microsoft",
    r"appdata\local\microsoft\windows",
    r"appdata\local\microsoft\windowsapps",
    r"appdata\roaming\microsoft",
    r"appdata\roaming\microsoft\windows",
    r"appdata\roaming\microsoft\windows\start menu",
    r"appdata\roaming\microsoft\windows\start menu\programs",
    r"appdata\roaming\microsoft\windows\start menu\programs\startup",
    r"appdata\roaming\npm",
    r"appdata\roaming\npm\node_modules",
    "desktop",
    "documents",
    "downloads",
    "pictures",
    "music",
    "videos",
    "favorites",
    "onedrive",
    ".cargo",
    ".rustup",
    ".nuget",
    ".dotnet",
    "scoop",
    r"scoop\apps",
];

/// True if deleting `path` (file or folder) must be refused.
pub fn is_denied_path(path: &str) -> bool {
    let p = norm(path);
    // Relative, empty, drive roots and UNC/device paths are refused outright.
    if p.len() < 4 || !p.as_bytes()[0].is_ascii_alphabetic() || p.get(1..3) != Some(":\\") || p.contains("\\..") {
        return true;
    }
    if denied_trees().iter().any(|t| paths::is_under(&p, t)) {
        return true;
    }
    if denied_exact().contains(&p) {
        return true;
    }
    let users = format!(r"{}\users\", system_drive());
    if let Some(rest) = p.strip_prefix(&users) {
        let rel = rest.split_once('\\').map(|(_, r)| r).unwrap_or("");
        if PROFILE_STRUCTURE.contains(&rel) {
            return true;
        }
    }
    false
}

fn split_hive(key: &str) -> Option<(String, String)> {
    let k = key.trim().trim_matches('\\').to_ascii_lowercase();
    let (hive, rest) = k.split_once('\\').unwrap_or((&k, ""));
    match hive {
        "hklm" | "hkey_local_machine" => Some(("hklm".into(), rest.to_string())),
        "hku" | "hkey_users" => {
            // Strip the SID so per-user rules match HKLM-style paths.
            let rest = rest.split_once('\\').map(|(_, r)| r).unwrap_or("");
            Some(("hku".into(), rest.to_string()))
        }
        _ => None,
    }
}

const DENIED_KEY_TREES: &[&str] = &[
    "system",
    "sam",
    "security",
    "hardware",
    "bcd00000000",
    r"software\policies",
    r"software\microsoft\windows nt\currentversion\winlogon",
    r"software\microsoft\windows nt\currentversion\image file execution options",
    r"software\microsoft\windows\currentversion\policies",
    r"software\microsoft\cryptography",
    r"software\microsoft\windows defender",
    r"software\microsoft\windows\currentversion\component based servicing",
    r"software\microsoft\windows\currentversion\winevt",
    r"software\classes\installer\components",
    r"software\snipe",
];

const DENIED_KEY_EXACT: &[&str] = &[
    "software",
    "software\\classes",
    r"software\classes\clsid",
    r"software\classes\interface",
    r"software\classes\typelib",
    r"software\classes\appid",
    r"software\classes\*",
    r"software\classes\directory",
    r"software\classes\folder",
    r"software\classes\allfilesystemobjects",
    r"software\classes\exefile",
    r"software\classes\lnkfile",
    r"software\classes\.exe",
    r"software\classes\.lnk",
    r"software\classes\.dll",
    r"software\classes\.bat",
    r"software\classes\.cmd",
    r"software\classes\installer",
    r"software\classes\installer\products",
    r"software\classes\installer\features",
    r"software\classes\local settings",
    r"software\wow6432node",
    r"software\wow6432node\microsoft",
    r"software\wow6432node\classes",
    r"software\microsoft",
    r"software\microsoft\windows",
    r"software\microsoft\windows\currentversion",
    r"software\microsoft\windows\currentversion\uninstall",
    r"software\microsoft\windows\currentversion\run",
    r"software\microsoft\windows\currentversion\runonce",
    r"software\microsoft\windows\currentversion\app paths",
    r"software\microsoft\windows\currentversion\explorer",
    r"software\microsoft\windows\currentversion\shareddlls",
    r"software\microsoft\windows nt",
    r"software\microsoft\windows nt\currentversion",
    "environment",
    "control panel",
];

const FIREWALL_RULES: &str = r"system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\firewallrules";

fn strip_wow(rest: &str) -> String {
    rest.replacen(r"software\wow6432node\", r"software\", 1)
}

/// True if deleting the whole registry key must be refused.
pub fn is_denied_key(key: &str) -> bool {
    let Some((_, rest)) = split_hive(key) else { return true };
    if rest.matches('\\').count() < 1 {
        return true;
    }
    let rest = strip_wow(&rest);
    DENIED_KEY_TREES.iter().any(|t| rest == *t || rest.starts_with(&format!("{t}\\")))
        || DENIED_KEY_EXACT.contains(&rest.as_str())
}

/// True if deleting a single value under `key` must be refused.
pub fn is_denied_value(key: &str) -> bool {
    let Some((_, rest)) = split_hive(key) else { return true };
    if rest == FIREWALL_RULES {
        return false;
    }
    let rest = strip_wow(&rest);
    DENIED_KEY_TREES.iter().any(|t| rest == *t || rest.starts_with(&format!("{t}\\")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_system_paths() {
        assert!(is_denied_path(r"C:\"));
        assert!(is_denied_path(r"C:\Windows\System32"));
        assert!(is_denied_path(r"C:\Program Files"));
        assert!(is_denied_path(r"C:\Program Files\Common Files"));
        assert!(is_denied_path(r"C:\Users\bob\AppData\Roaming"));
        assert!(is_denied_path(r"C:\Users\bob"));
        assert!(is_denied_path(r"relative\path"));
        assert!(is_denied_path(r"\\server\share\x"));
        assert!(is_denied_path(r"C:\Program Files\App\..\..\Windows"));
        assert!(!is_denied_path(r"C:\Program Files\7-Zip"));
        assert!(!is_denied_path(r"C:\Users\bob\AppData\Roaming\Vendor\App"));
    }

    #[test]
    fn denies_system_keys() {
        assert!(is_denied_key(r"HKLM\SOFTWARE"));
        assert!(is_denied_key(r"HKLM\SOFTWARE\Microsoft"));
        assert!(is_denied_key(r"HKLM\SYSTEM\CurrentControlSet\Services\Foo"));
        assert!(is_denied_key(r"HKLM\SOFTWARE\WOW6432Node\Microsoft"));
        assert!(is_denied_key(r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run"));
        assert!(is_denied_key(r"HKCR\.exe"));
        assert!(!is_denied_key(r"HKLM\SOFTWARE\Vendor\App"));
        assert!(!is_denied_key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\App"));
        assert!(!is_denied_value(
            r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        ));
        assert!(is_denied_value(r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager"));
        assert!(!is_denied_value(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"));
    }
}
