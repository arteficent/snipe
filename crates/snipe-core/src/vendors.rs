//! Tamper-protected security products and the authorization each one needs to
//! uninstall (removal ladder Tier 0a, §5.5), plus a `Secret` wrapper that keeps
//! that authorization out of logs, journals and `Debug` output.
//!
//! Every entry here must be verified against the vendor's current documentation
//! before it is relied on; Snipe never guesses a property name. The table only
//! *describes* the authorized path — it never stores a secret.

use serde::{Deserialize, Serialize};
use std::fmt;

/// An uninstall authorization (password or token) that must never be logged.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The raw value, exposed only at the point of use (never logged).
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Only a strict character set is accepted, so the value can be passed as a
    /// parsed argument and never reaches a shell.
    pub fn is_well_formed(&self) -> bool {
        !self.0.is_empty()
            && self.0.len() <= 256
            && self.0.chars().all(|c| c.is_ascii_alphanumeric() || "-_.:@+/=".contains(c))
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Best-effort wipe so the plaintext does not linger in freed memory.
        unsafe {
            for b in self.0.as_bytes_mut() {
                std::ptr::write_volatile(b, 0);
            }
        }
    }
}

/// How a vendor's uninstaller consumes its authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthKind {
    /// An MSI property, e.g. `UNINSTALL_PASSWORD=<secret>`.
    MsiProperty,
    /// An argument to the vendor's own CLI.
    VendorCli,
}

/// A tamper-protected product and its authorized removal path.
#[derive(Debug, Clone)]
pub struct Vendor {
    /// Lower-case substrings matched against the product or publisher name.
    pub needles: &'static [&'static str],
    pub product: &'static str,
    pub kind: AuthKind,
    /// MSI property name or CLI argument flag that carries the secret.
    pub property: &'static str,
    /// Where the owner obtains the secret.
    pub instructions: &'static str,
}

/// The verified table. Expand only with documented, tested entries.
pub static VENDORS: &[Vendor] = &[
    Vendor {
        needles: &["cortex xdr", "palo alto", "traps", "cyvera"],
        product: "Cortex XDR",
        kind: AuthKind::MsiProperty,
        property: "uninstall_password",
        instructions: "Cortex XDR management console → Endpoint Administration → Uninstall password. \
            On managed machines, the console's own \"Uninstall\" action is the cleanest route.",
    },
    Vendor {
        needles: &["crowdstrike", "falcon"],
        product: "CrowdStrike Falcon",
        kind: AuthKind::MsiProperty,
        property: "maintenance_token",
        instructions: "CrowdStrike console → Host setup and management → maintenance token.",
    },
    Vendor {
        needles: &["sentinelone", "sentinel agent"],
        product: "SentinelOne",
        kind: AuthKind::VendorCli,
        property: "passphrase",
        instructions: "SentinelOne management console → Sentinels → Actions → show passphrase.",
    },
    Vendor {
        needles: &["sophos"],
        product: "Sophos",
        kind: AuthKind::MsiProperty,
        property: "tamper_password",
        instructions: "Sophos Central → Global Settings → Tamper Protection password.",
    },
];

/// The vendor entry matching this product or publisher name, if any.
pub fn lookup(name: &str, publisher: Option<&str>) -> Option<&'static Vendor> {
    let hay = format!("{} {}", name, publisher.unwrap_or_default()).to_ascii_lowercase();
    VENDORS.iter().find(|v| v.needles.iter().any(|n| hay.contains(n)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_redacted() {
        let s = Secret::new("p@ss-word_1");
        assert_eq!(format!("{s:?}"), "Secret(***)");
        assert_eq!(format!("{s}"), "***");
        assert!(s.is_well_formed());
    }

    #[test]
    fn secret_rejects_shell_metacharacters() {
        assert!(!Secret::new("a & b").is_well_formed());
        assert!(!Secret::new("x; rm").is_well_formed());
        assert!(!Secret::new("").is_well_formed());
    }

    #[test]
    fn cortex_is_matched() {
        let v = lookup("Cortex XDR", Some("Palo Alto Networks")).expect("match");
        assert_eq!(v.product, "Cortex XDR");
        assert_eq!(v.kind, AuthKind::MsiProperty);
    }

    #[test]
    fn ordinary_software_has_no_vendor() {
        assert!(lookup("7-Zip 24.08 (x64)", Some("Igor Pavlov")).is_none());
    }
}
