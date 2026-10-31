//! Path helpers: environment expansion, command-line parsing and Windows-dir checks.

use std::sync::OnceLock;

pub fn windows_dir() -> &'static str {
    static DIR: OnceLock<String> = OnceLock::new();
    DIR.get_or_init(|| {
        std::env::var("SystemRoot")
            .or_else(|_| std::env::var("windir"))
            .unwrap_or_else(|_| r"C:\Windows".to_string())
    })
}

fn normalize(path: &str) -> String {
    path.trim()
        .trim_matches('"')
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

/// True if `path` equals `root` or lies beneath it (case-insensitive).
pub fn is_under(path: &str, root: &str) -> bool {
    let p = normalize(path);
    let r = normalize(root);
    !r.is_empty() && (p == r || p.starts_with(&format!("{r}\\")))
}

pub fn is_windows_path(path: &str) -> bool {
    is_under(path, windows_dir())
}

/// Expands `%VAR%` references and NT-style prefixes used in service image paths.
pub fn expand(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    for prefix in [r"\??\", r"\\?\"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.to_string();
        }
    }
    let starts_with_ci = |s: &str, p: &str| s.get(..p.len()).is_some_and(|h| h.eq_ignore_ascii_case(p));
    if starts_with_ci(&s, r"\SystemRoot\") {
        s = format!(r"{}\{}", windows_dir(), &s[12..]);
    } else if starts_with_ci(&s, r"System32\") {
        s = format!(r"{}\{}", windows_dir(), s);
    }

    let mut out = String::with_capacity(s.len());
    let mut rest = s.as_str();
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(val) if !name.is_empty() => out.push_str(&val),
                    _ => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// Extracts the executable path from a command line such as
/// `"C:\Program Files\App\app.exe" --flag` or `C:\Tools\app.exe /S`.
pub fn exe_from_command(cmd: &str) -> Option<String> {
    let cmd = expand(cmd);
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return None;
    }
    if let Some(rest) = cmd.strip_prefix('"') {
        return rest.find('"').map(|end| rest[..end].to_string());
    }
    let lower = cmd.to_ascii_lowercase();
    for ext in [".exe", ".com", ".bat", ".cmd", ".dll", ".sys"] {
        if let Some(pos) = lower.find(ext) {
            return Some(cmd[..pos + ext.len()].to_string());
        }
    }
    Some(cmd.split_whitespace().next()?.to_string())
}

pub fn parent_dir(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches('\\');
    trimmed.rfind('\\').map(|i| trimmed[..i].to_string()).filter(|p| !p.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_exe_paths() {
        assert_eq!(
            exe_from_command(r#""C:\Program Files\App\unins000.exe" /SILENT"#).as_deref(),
            Some(r"C:\Program Files\App\unins000.exe")
        );
        assert_eq!(
            exe_from_command(r"C:\Program Files\App\svc.exe -k netsvcs").as_deref(),
            Some(r"C:\Program Files\App\svc.exe")
        );
    }

    #[test]
    fn is_under_respects_boundaries() {
        assert!(is_under(r"C:\Windows\System32\svchost.exe", r"C:\Windows"));
        assert!(is_under(r"c:\windows", r"C:\Windows\"));
        assert!(!is_under(r"C:\WindowsApps\foo", r"C:\Windows"));
    }

    #[test]
    fn parent_dir_works() {
        assert_eq!(parent_dir(r"C:\a\b\c.exe").as_deref(), Some(r"C:\a\b"));
        assert_eq!(parent_dir("c.exe"), None);
    }
}
