//! Process execution: uninstallers run inside a Job Object so the engine waits for every child
//! (many uninstallers relaunch themselves from %TEMP% and exit immediately).

use snipe_collectors::util::{hidden_command, to_wide};
use std::ffi::c_void;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JobObjectBasicAccountingInformation, QueryInformationJobObject,
};
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, GetExitCodeProcess, PROCESS_INFORMATION,
    ResumeThread, STARTUPINFOW, WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: owned handle closed once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[derive(Debug)]
pub struct RunResult {
    pub exit_code: u32,
    pub timed_out: bool,
}

/// Starts `exe args` suspended, places it in a job, resumes it and waits for the whole tree.
pub fn run_in_job(exe: &str, args: &str, timeout: Duration) -> io::Result<RunResult> {
    let exe_w = to_wide(exe);
    let mut cmdline = to_wide(&format!("\"{exe}\" {args}"));
    let cwd = Path::new(exe).parent().map(|p| to_wide(&p.to_string_lossy()));
    let start = Instant::now();
    // SAFETY: all buffers outlive the calls; handles are wrapped for cleanup.
    unsafe {
        let job = Handle(CreateJobObjectW(None, PCWSTR::null()).map_err(io::Error::other)?);
        let si = STARTUPINFOW { cb: size_of::<STARTUPINFOW>() as u32, ..Default::default() };
        let mut pi = PROCESS_INFORMATION::default();
        CreateProcessW(
            PCWSTR(exe_w.as_ptr()),
            Some(PWSTR(cmdline.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            None,
            cwd.as_ref().map(|c| PCWSTR(c.as_ptr())).unwrap_or(PCWSTR::null()),
            &si,
            &mut pi,
        )
        .map_err(|e| io::Error::from_raw_os_error(e.code().0 & 0xFFFF))?;
        let process = Handle(pi.hProcess);
        let thread = Handle(pi.hThread);
        let in_job = AssignProcessToJobObject(job.0, process.0).is_ok();
        ResumeThread(thread.0);

        let ms = timeout.as_millis().min(u32::MAX as u128 - 1) as u32;
        let waited = WaitForSingleObject(process.0, ms);
        let mut code = 0u32;
        let _ = GetExitCodeProcess(process.0, &mut code);
        if waited != WAIT_OBJECT_0 {
            return Ok(RunResult { exit_code: code, timed_out: true });
        }
        if in_job {
            loop {
                let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
                let ok = QueryInformationJobObject(
                    Some(job.0),
                    JobObjectBasicAccountingInformation,
                    &mut info as *mut _ as *mut c_void,
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    None,
                )
                .is_ok();
                if !ok || info.ActiveProcesses == 0 {
                    break;
                }
                if start.elapsed() > timeout {
                    return Ok(RunResult { exit_code: code, timed_out: true });
                }
                std::thread::sleep(Duration::from_millis(400));
            }
        }
        Ok(RunResult { exit_code: code, timed_out: false })
    }
}

/// Runs a console tool hidden and captures its output.
pub fn run_tool<I, S>(exe: impl AsRef<std::ffi::OsStr>, args: I) -> io::Result<(i32, String)>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let out = hidden_command(exe).args(args).output()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    let err = String::from_utf8_lossy(&out.stderr);
    if !err.trim().is_empty() {
        text.push('\n');
        text.push_str(err.trim());
    }
    Ok((out.status.code().unwrap_or(-1), text))
}

/// Last non-empty line of tool output, for error messages.
pub fn last_line(text: &str) -> String {
    text.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").trim().to_string()
}
