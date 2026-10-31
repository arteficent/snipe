//! Registry helpers working on [`RegPath`]: open, delete, and `.reg` backup/restore.

use snipe_collectors::util::{hidden_command, system32};
use snipe_core::RegPath;
use std::io;
use std::path::Path;
use winreg::RegKey;
use winreg::enums::{
    HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_ALL_ACCESS, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY, RegType,
};

fn split(reg: &RegPath) -> io::Result<(RegKey, &str, &'static str)> {
    let (hive, rest) = reg.key.split_once('\\').unwrap_or((&reg.key, ""));
    match hive.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => Ok((RegKey::predef(HKEY_LOCAL_MACHINE), rest, "HKEY_LOCAL_MACHINE")),
        "HKU" | "HKEY_USERS" => Ok((RegKey::predef(HKEY_USERS), rest, "HKEY_USERS")),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unsupported hive in {}", reg.key))),
    }
}

fn view(reg: &RegPath) -> u32 {
    if reg.wow32 { KEY_WOW64_32KEY } else { KEY_WOW64_64KEY }
}

pub fn open(reg: &RegPath, write: bool) -> io::Result<RegKey> {
    let (root, rest, _) = split(reg)?;
    let access = if write { KEY_ALL_ACCESS } else { KEY_READ };
    root.open_subkey_with_flags(rest, access | view(reg))
}

pub fn exists(reg: &RegPath) -> bool {
    open(reg, false).is_ok()
}

pub fn delete_key(reg: &RegPath) -> io::Result<()> {
    let (root, rest, _) = split(reg)?;
    let (parent, leaf) = rest
        .rsplit_once('\\')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "refusing to delete a top-level key"))?;
    root.open_subkey_with_flags(parent, KEY_ALL_ACCESS | view(reg))?.delete_subkey_all(leaf)
}

pub fn delete_value(reg: &RegPath, name: &str) -> io::Result<()> {
    open(reg, true)?.delete_value(name)
}

fn reg_view_arg(reg: &RegPath) -> &'static str {
    if reg.wow32 { "/reg:32" } else { "/reg:64" }
}

/// Exports a whole key with `reg.exe export`.
pub fn export_key(reg: &RegPath, file: &Path) -> io::Result<()> {
    let out = hidden_command(system32("reg.exe"))
        .arg("export")
        .arg(&reg.key)
        .arg(file)
        .args(["/y", reg_view_arg(reg)])
        .output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("reg export failed: {}", String::from_utf8_lossy(&out.stderr).trim())))
    }
}

/// Imports a `.reg` file into the given registry view.
pub fn import(file: &Path, wow32: bool) -> io::Result<()> {
    let out = hidden_command(system32("reg.exe"))
        .arg("import")
        .arg(file)
        .arg(if wow32 { "/reg:32" } else { "/reg:64" })
        .output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("reg import failed: {}", String::from_utf8_lossy(&out.stderr).trim())))
    }
}

fn reg_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn hex_list(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(",")
}

/// Renders one value as a `.reg` line.
pub fn format_value_line(name: &str, vtype: u32, bytes: &[u8]) -> String {
    let lhs = if name.is_empty() { "@".to_string() } else { format!("\"{}\"", reg_escape(name)) };
    let rhs = match vtype {
        1 => {
            let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            let text = String::from_utf16_lossy(&units);
            format!("\"{}\"", reg_escape(text.trim_end_matches('\0')))
        }
        4 if bytes.len() == 4 => format!("dword:{:08x}", u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
        3 => format!("hex:{}", hex_list(bytes)),
        t => format!("hex({t:x}):{}", hex_list(bytes)),
    };
    format!("{lhs}={rhs}")
}

/// Writes a `.reg` file (UTF-16LE with BOM) containing a single value.
pub fn export_value(reg: &RegPath, name: &str, file: &Path) -> io::Result<()> {
    let (_, rest, hive_name) = split(reg)?;
    let value = open(reg, false)?.get_raw_value(name)?;
    let vtype = value.vtype as u32;
    let text = format!(
        "Windows Registry Editor Version 5.00\r\n\r\n[{hive_name}\\{rest}]\r\n{}\r\n",
        format_value_line(name, vtype, &value.bytes)
    );
    let mut out = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    std::fs::write(file, out)
}

pub fn read_raw(reg: &RegPath, name: &str) -> io::Result<(RegType, Vec<u8>)> {
    let v = open(reg, false)?.get_raw_value(name)?;
    Ok((v.vtype, v.bytes.to_vec()))
}

pub fn write_raw(reg: &RegPath, name: &str, vtype: RegType, bytes: Vec<u8>) -> io::Result<()> {
    let value = winreg::RegValue { bytes: bytes.into(), vtype };
    open(reg, true)?.set_raw_value(name, &value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_reg_values() {
        let sz: Vec<u8> = "C:\\a\"b\0".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(format_value_line("Path", 1, &sz), r#""Path"="C:\\a\"b""#);
        assert_eq!(format_value_line("", 4, &[1, 0, 0, 0]), "@=dword:00000001");
        assert_eq!(format_value_line("x", 2, &[0x41, 0]), "\"x\"=hex(2):41,00");
    }
}
