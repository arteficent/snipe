//! Date helpers that avoid pulling in a full date/time crate.

const FILETIME_UNIX_DIFF_SECS: i64 = 11_644_473_600;

/// Converts days since 1970-01-01 into (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

fn format_ymd(y: i64, m: u32, d: u32) -> String {
    format!("{y:04}-{m:02}-{d:02}")
}

/// Formats a FILETIME-style tick count (100ns since 1601-01-01 UTC) as YYYY-MM-DD.
pub fn from_filetime_ticks(ticks: i64) -> Option<String> {
    if ticks <= 0 {
        return None;
    }
    let unix_secs = ticks / 10_000_000 - FILETIME_UNIX_DIFF_SECS;
    let (y, m, d) = civil_from_days(unix_secs.div_euclid(86_400));
    Some(format_ymd(y, m, d))
}

/// Formats Unix seconds as YYYY-MM-DD.
pub fn from_unix_secs(secs: i64) -> String {
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format_ymd(y, m, d)
}

/// Parses the registry `InstallDate` value (`YYYYMMDD`) into YYYY-MM-DD.
pub fn from_yyyymmdd(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.len() != 8 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (y, rest) = s.split_at(4);
    let (m, d) = rest.split_at(2);
    let (mi, di): (u32, u32) = (m.parse().ok()?, d.parse().ok()?);
    if !(1..=12).contains(&mi) || !(1..=31).contains(&di) {
        return None;
    }
    Some(format!("{y}-{m}-{d}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_registry_dates() {
        assert_eq!(from_yyyymmdd("20240315").as_deref(), Some("2024-03-15"));
        assert_eq!(from_yyyymmdd("2024-03-15"), None);
        assert_eq!(from_yyyymmdd("20241345"), None);
    }

    #[test]
    fn converts_filetime() {
        // 2021-01-01T00:00:00Z
        assert_eq!(from_filetime_ticks(132_539_328_000_000_000).as_deref(), Some("2021-01-01"));
        assert_eq!(from_unix_secs(0), "1970-01-01");
    }
}
