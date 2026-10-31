//! CSV / JSON export of the inventory.

use snipe_core::Item;

fn csv_field(s: &str) -> String {
    // Leading formula characters are neutralised so spreadsheets don't execute them.
    let s = if s.starts_with(['=', '+', '-', '@']) { format!("'{s}") } else { s.to_string() };
    if s.contains([',', '"', '\n', '\r']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s }
}

pub fn to_csv(items: &[Item]) -> String {
    let mut out = String::from(
        "Name,Version,Publisher,Type,Scope,User,Architecture,Protection,System flagged,Manager,Size (bytes),Installed,Location,Executable,Signature,Signer,Risk,Risk reasons,Source\r\n",
    );
    for i in items {
        let row = [
            i.name.clone(),
            i.version.clone().unwrap_or_default(),
            i.publisher.clone().unwrap_or_default(),
            enum_text(&i.kind),
            enum_text(&i.scope),
            i.user.clone().unwrap_or_default(),
            enum_text(&i.arch),
            enum_text(&i.protection),
            i.hidden.to_string(),
            i.manager.clone().unwrap_or_default(),
            i.size_bytes.map(|s| s.to_string()).unwrap_or_default(),
            i.install_date.clone().unwrap_or_default(),
            i.install_location.clone().unwrap_or_default(),
            i.executable.clone().unwrap_or_default(),
            i.signature.as_ref().map(|s| enum_text(&s.status)).unwrap_or_default(),
            i.signature.as_ref().and_then(|s| s.signer.clone()).unwrap_or_default(),
            i.risk.to_string(),
            i.risk_reasons.join("; "),
            i.source.clone(),
        ];
        out.push_str(&row.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(","));
        out.push_str("\r\n");
    }
    out
}

pub fn to_json(items: &[Item]) -> String {
    serde_json::to_string_pretty(items).unwrap_or_default()
}

/// Serializes a unit enum variant to its plain string form.
fn enum_text<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_csv() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("=cmd()"), "'=cmd()");
    }
}
