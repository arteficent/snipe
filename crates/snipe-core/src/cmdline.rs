//! Parsing of uninstall command lines. Commands are never handed to a shell.

use crate::paths;

/// A command split into an executable and its raw (verbatim) argument string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitCommand {
    pub exe: String,
    pub args: String,
}

/// Splits `"C:\Path\app.exe" /x` or `C:\Program Files\App\un.exe /S` into exe + args.
pub fn split_command(raw: &str) -> Option<SplitCommand> {
    let cmd = paths::expand(raw);
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return None;
    }
    if let Some(rest) = cmd.strip_prefix('"') {
        let end = rest.find('"')?;
        let exe = rest[..end].trim().to_string();
        let args = rest[end + 1..].trim().to_string();
        return (!exe.is_empty()).then_some(SplitCommand { exe, args });
    }
    let exe = paths::exe_from_command(cmd)?;
    let args = cmd.get(exe.len()..).unwrap_or_default().trim().to_string();
    Some(SplitCommand { exe, args })
}

/// Finds a `{GUID}` product code inside a string.
pub fn find_guid(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while let Some(off) = s[i..].find('{') {
        let start = i + off;
        if let Some(candidate) = s.get(start..start + 38)
            && is_guid(candidate)
        {
            return Some(candidate.to_ascii_uppercase());
        }
        i = start + 1;
        if i >= bytes.len() {
            break;
        }
    }
    None
}

pub fn is_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 38
        && b[0] == b'{'
        && b[37] == b'}'
        && b[1..37].iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// `msiexec /I{GUID}` in an UninstallString opens maintenance mode; map it to a real uninstall.
pub fn msi_product_from_command(raw: &str) -> Option<String> {
    let split = split_command(raw)?;
    let file = split.exe.rsplit('\\').next().unwrap_or(&split.exe).to_ascii_lowercase();
    if file == "msiexec.exe" || file == "msiexec" {
        find_guid(&split.args)
    } else {
        None
    }
}

/// Package names passed to package-manager CLIs are restricted to a safe character set.
pub fn is_safe_package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 214
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '/' | '.' | '_' | '-' | '+'))
}

/// Names for services, tasks, features etc. must not contain quotes or control characters.
pub fn is_safe_identifier(name: &str) -> bool {
    !name.is_empty() && !name.starts_with('-') && !name.chars().any(|c| c == '"' || c.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_quoted_and_unquoted() {
        assert_eq!(
            split_command(r#""C:\Program Files\App\unins000.exe" /SILENT"#),
            Some(SplitCommand { exe: r"C:\Program Files\App\unins000.exe".into(), args: "/SILENT".into() })
        );
        assert_eq!(
            split_command(r"C:\Program Files\App\uninstall.exe /S _?=C:\x"),
            Some(SplitCommand { exe: r"C:\Program Files\App\uninstall.exe".into(), args: r"/S _?=C:\x".into() })
        );
        assert_eq!(split_command(""), None);
        assert_eq!(split_command("\"unterminated"), None);
    }

    #[test]
    fn maps_msiexec_commands() {
        assert_eq!(
            msi_product_from_command("MsiExec.exe /I{90160000-008C-0000-1000-0000000FF1CE}").as_deref(),
            Some("{90160000-008C-0000-1000-0000000FF1CE}")
        );
        assert_eq!(msi_product_from_command(r"C:\x\unins000.exe"), None);
    }

    #[test]
    fn package_names() {
        assert!(is_safe_package_name("@angular/cli"));
        assert!(is_safe_package_name("ripgrep"));
        assert!(!is_safe_package_name("--global"));
        assert!(!is_safe_package_name("a b"));
        assert!(!is_safe_package_name("a&calc"));
    }

    #[test]
    fn parsers_never_panic() {
        // Deterministic pseudo-random fuzzing of the parsers.
        let alphabet: Vec<char> = "\"\\ {}-/.exeEXE%:abc0123456789éü\t".chars().collect();
        let mut state: u64 = 0x1234_5678;
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = (state % 48) as usize;
            let s: String = (0..len)
                .map(|i| alphabet[((state >> (i % 50)) as usize + i) % alphabet.len()])
                .collect();
            let _ = split_command(&s);
            let _ = find_guid(&s);
            let _ = msi_product_from_command(&s);
            let _ = paths::exe_from_command(&s);
            let _ = crate::deny::is_denied_path(&s);
        }
    }
}
