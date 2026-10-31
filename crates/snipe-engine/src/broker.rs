//! Elevated broker: `snipe.exe --broker <pipe> <ui-pid>` serves requests over a named pipe.
//!
//! * The pipe DACL admits only SYSTEM, Administrators and the UI's user (with a medium
//!   integrity label so the non-elevated UI can connect).
//! * The broker only accepts the UI process it was launched for (checked by PID and image path),
//!   and the UI only talks to the broker process it launched (checked by server PID).
//! * Requests carry item IDs only; the broker re-derives every path and command from its own scan.

use crate::engine::Engine;
use crate::protocol::{Request, Response, ScanEvent};
use crate::safety;
use snipe_collectors::util::{is_elevated, to_wide};
use std::ffi::c_void;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL, LocalFree, WAIT_OBJECT_0};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    GetProcessId, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW, WaitForSingleObject,
};
use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
use windows::core::{PCWSTR, PWSTR, w};

const MAX_REQUEST: u64 = 1 << 20;
const MAX_RESPONSE: u64 = 256 << 20;

struct Owned(HANDLE);

// SAFETY: kernel handles may be used from any thread.
unsafe impl Send for Owned {}

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: owned handle closed once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn valid_pipe_name(name: &str) -> bool {
    name.starts_with("snipe-broker-") && name.len() < 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn read_line_limited(reader: &mut impl BufRead, limit: u64) -> std::io::Result<Option<String>> {
    let mut line = String::new();
    let n = reader.by_ref().take(limit).read_line(&mut line)?;
    if n == 0 {
        return Ok(None);
    }
    if !line.ends_with('\n') && n as u64 >= limit {
        return Err(std::io::Error::other("message too large"));
    }
    Ok(Some(line))
}

fn process_image(pid: u32) -> Option<String> {
    // SAFETY: handle closed by Owned.
    unsafe {
        let h = Owned(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?);
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len).ok()?;
        Some(String::from_utf16_lossy(&buf[..len as usize]).to_ascii_lowercase())
    }
}

fn process_user_sid(pid: u32) -> Option<String> {
    // SAFETY: handles are closed; the token buffer is pointer-aligned.
    unsafe {
        let process = Owned(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?);
        let mut token = HANDLE::default();
        OpenProcessToken(process.0, TOKEN_QUERY, &mut token).ok()?;
        let token = Owned(token);
        let mut storage = [0u64; 64];
        let mut needed = 0u32;
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(storage.as_mut_ptr().cast::<c_void>()),
            size_of_val(&storage) as u32,
            &mut needed,
        )
        .ok()?;
        let user = &*storage.as_ptr().cast::<TOKEN_USER>();
        let mut text = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut text).ok()?;
        let sid = text.to_string().ok();
        let _ = LocalFree(Some(HLOCAL(text.0 as *mut c_void)));
        sid
    }
}

/// Entry point of `snipe.exe --broker <pipe> <ui-pid>`.
pub fn serve(pipe: &str, client_pid: u32) -> Result<(), String> {
    if !is_elevated() {
        return Err("the broker must run elevated".into());
    }
    if !valid_pipe_name(pipe) {
        return Err("invalid pipe name".into());
    }
    let own = std::env::current_exe().map_err(|e| e.to_string())?.to_string_lossy().to_ascii_lowercase();
    if process_image(client_pid).as_deref() != Some(own.as_str()) {
        return Err("the requesting process is not Snipe".into());
    }
    let sid = process_user_sid(client_pid).ok_or("cannot identify the requesting user")?;
    let sddl = to_wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{sid})S:(ML;;NW;;;ME)"));
    let name = to_wide(&format!(r"\\.\pipe\{pipe}"));

    // SAFETY: the security descriptor outlives CreateNamedPipeW; the pipe handle is moved into a File.
    let file = unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), SDDL_REVISION_1, &mut sd, None)
            .map_err(|e| e.message().to_string())?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };
        let handle = CreateNamedPipeW(
            PCWSTR(name.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            64 * 1024,
            64 * 1024,
            0,
            Some(&sa),
        );
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        if handle.is_invalid() {
            return Err("could not create the broker pipe".into());
        }

        let connected = Arc::new(AtomicBool::new(false));
        let flag = connected.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(60));
            if !flag.load(Ordering::SeqCst) {
                std::process::exit(2);
            }
        });
        if let Err(e) = ConnectNamedPipe(handle, None)
            && e.code() != ERROR_PIPE_CONNECTED.to_hresult()
        {
            return Err(e.message().to_string());
        }
        connected.store(true, Ordering::SeqCst);
        let mut pid = 0u32;
        GetNamedPipeClientProcessId(handle, &mut pid).map_err(|e| e.message().to_string())?;
        if pid != client_pid {
            return Err("unexpected client connected to the broker".into());
        }
        File::from_raw_handle(handle.0 as _)
    };

    safety::purge_older_than(30);
    let mut reader = BufReader::new(file.try_clone().map_err(|e| e.to_string())?);
    let mut writer = file;
    let mut engine = Engine::new();
    while let Some(line) = read_line_limited(&mut reader, MAX_REQUEST).map_err(|e| e.to_string())? {
        let request: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                write_response(&mut writer, &Response::Err { message: format!("bad request: {e}") })?;
                continue;
            }
        };
        let shutdown = matches!(request, Request::Shutdown);
        let mut write_error = None;
        let result = engine.handle(request, &mut |event| {
            if write_error.is_none()
                && let Err(e) = write_response(&mut writer, &Response::Event { event })
            {
                write_error = Some(e);
            }
        });
        if let Some(e) = write_error {
            return Err(e);
        }
        let response = match result {
            Ok(value) => Response::Ok { value },
            Err(message) => Response::Err { message },
        };
        write_response(&mut writer, &response)?;
        if shutdown {
            break;
        }
    }
    Ok(())
}

fn write_response(writer: &mut File, response: &Response) -> Result<(), String> {
    let mut bytes = serde_json::to_vec(response).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    writer.write_all(&bytes).map_err(|e| e.to_string())
}

/// UI-side connection to an elevated broker.
pub struct BrokerClient {
    reader: BufReader<File>,
    writer: File,
    process: Owned,
}

impl BrokerClient {
    /// Starts the broker through UAC and connects to it.
    pub fn launch() -> Result<Self, String> {
        use std::hash::{BuildHasher, Hasher};
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u32(std::process::id());
        let pipe = format!("snipe-broker-{:016x}", hasher.finish());

        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let exe_w = to_wide(&exe.to_string_lossy());
        let params = to_wide(&format!("--broker {pipe} {}", std::process::id()));
        let mut info = SHELLEXECUTEINFOW {
            cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: w!("runas"),
            lpFile: PCWSTR(exe_w.as_ptr()),
            lpParameters: PCWSTR(params.as_ptr()),
            nShow: SW_HIDE.0,
            ..Default::default()
        };
        // SAFETY: all strings outlive the call.
        unsafe { ShellExecuteExW(&mut info) }.map_err(|e| {
            if e.code() == ERROR_CANCELLED.to_hresult() {
                "Administrator permission was declined.".to_string()
            } else {
                format!("Could not start the administrator session: {}", e.message())
            }
        })?;
        let process = Owned(info.hProcess);

        let path = format!(r"\\.\pipe\{pipe}");
        let deadline = Instant::now() + Duration::from_secs(60);
        let file = loop {
            match std::fs::OpenOptions::new().read(true).write(true).open(&path) {
                Ok(f) => break f,
                Err(_) if Instant::now() < deadline => {
                    // SAFETY: valid process handle.
                    if unsafe { WaitForSingleObject(process.0, 0) } == WAIT_OBJECT_0 {
                        return Err("The administrator session exited unexpectedly.".into());
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => return Err(format!("Could not connect to the administrator session: {e}")),
            }
        };
        let mut server_pid = 0u32;
        // SAFETY: valid pipe and process handles.
        unsafe {
            GetNamedPipeServerProcessId(HANDLE(file.as_raw_handle()), &mut server_pid).map_err(|e| e.message().to_string())?;
            if server_pid != GetProcessId(process.0) {
                return Err("Unexpected process on the broker pipe.".into());
            }
        }
        Ok(Self { reader: BufReader::new(file.try_clone().map_err(|e| e.to_string())?), writer: file, process })
    }

    pub fn is_alive(&self) -> bool {
        // SAFETY: valid process handle.
        unsafe { WaitForSingleObject(self.process.0, 0) != WAIT_OBJECT_0 }
    }

    pub fn call(&mut self, request: &Request, emit: &mut dyn FnMut(ScanEvent)) -> Result<serde_json::Value, String> {
        let mut bytes = serde_json::to_vec(request).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        self.writer.write_all(&bytes).map_err(|e| format!("administrator session lost: {e}"))?;
        loop {
            let line = read_line_limited(&mut self.reader, MAX_RESPONSE)
                .map_err(|e| e.to_string())?
                .ok_or("administrator session closed")?;
            match serde_json::from_str::<Response>(&line).map_err(|e| e.to_string())? {
                Response::Event { event } => emit(event),
                Response::Ok { value } => return Ok(value),
                Response::Err { message } => return Err(message),
            }
        }
    }
}

impl Drop for BrokerClient {
    fn drop(&mut self) {
        let _ = self.call(&Request::Shutdown, &mut |_| {});
    }
}
