//! Scheduled tasks via the Task Scheduler COM API.

use snipe_core::{CollectResult, Collector, Item, ItemKind, Protection, Scope, UninstallMethod, paths};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize};
use windows::Win32::System::TaskScheduler::{
    IExecAction, IRegisteredTask, ITaskFolder, ITaskService, TASK_ACTION_EXEC, TASK_ENUM_HIDDEN, TASK_STATE_DISABLED,
    TASK_STATE_QUEUED, TASK_STATE_READY, TASK_STATE_RUNNING, TaskScheduler,
};
use windows::Win32::System::Variant::{VARIANT, VT_I4};
use windows::core::{BSTR, Interface};

pub struct TasksCollector;

fn variant_i4(value: i32) -> VARIANT {
    let mut v = VARIANT::default();
    // SAFETY: writing the discriminant and the matching union member.
    unsafe {
        let inner = &mut *v.Anonymous.Anonymous;
        inner.vt = VT_I4;
        inner.Anonymous.lVal = value;
    }
    v
}

/// Calls a COM getter that returns its BSTR through an out-parameter.
fn bstr_out(f: impl FnOnce(*mut BSTR) -> windows::core::Result<()>) -> String {
    let mut value = BSTR::default();
    f(&mut value).map(|_| value.to_string()).unwrap_or_default()
}

struct ComGuard;

impl Drop for ComGuard {
    fn drop(&mut self) {
        // SAFETY: balanced with a successful CoInitializeEx on this thread.
        unsafe { CoUninitialize() };
    }
}

impl Collector for TasksCollector {
    fn id(&self) -> &'static str {
        "tasks"
    }

    fn label(&self) -> &'static str {
        "Scheduled tasks"
    }

    fn collect(&self) -> CollectResult<Vec<Item>> {
        // SAFETY: COM is initialised for this thread for the duration of the call.
        unsafe {
            let _guard = CoInitializeEx(None, COINIT_MULTITHREADED).is_ok().then_some(ComGuard);
            let service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;
            let empty = VARIANT::default();
            service.Connect(&empty, &empty, &empty, &empty)?;
            let root = service.GetFolder(&BSTR::from("\\"))?;
            let mut items = Vec::new();
            walk(&root, &mut items);
            Ok(items)
        }
    }
}

unsafe fn walk(folder: &ITaskFolder, items: &mut Vec<Item>) {
    // SAFETY: plain COM calls on valid interfaces.
    unsafe {
        if let Ok(tasks) = folder.GetTasks(TASK_ENUM_HIDDEN.0) {
            for i in 1..=tasks.Count().unwrap_or(0) {
                if let Ok(task) = tasks.get_Item(&variant_i4(i))
                    && let Ok(item) = read_task(&task)
                {
                    items.push(item);
                }
            }
        }
        if let Ok(folders) = folder.GetFolders(0) {
            for i in 1..=folders.Count().unwrap_or(0) {
                if let Ok(sub) = folders.get_Item(&variant_i4(i)) {
                    walk(&sub, items);
                }
            }
        }
    }
}

unsafe fn read_task(task: &IRegisteredTask) -> windows::core::Result<Item> {
    // SAFETY: plain COM calls on valid interfaces.
    unsafe {
        let path = task.Path()?.to_string();
        let name = task.Name()?.to_string();
        let mut item = Item::new(ItemKind::Task, name, path.clone());
        let system = path.to_ascii_lowercase().starts_with(r"\microsoft\");

        let state = match task.State()? {
            TASK_STATE_DISABLED => "Disabled",
            TASK_STATE_QUEUED => "Queued",
            TASK_STATE_READY => "Ready",
            TASK_STATE_RUNNING => "Running",
            _ => "Unknown",
        };
        item.detail("Task path", path.clone());
        item.detail("State", state);

        if let Ok(def) = task.Definition() {
            if let Ok(info) = def.RegistrationInfo() {
                item.publisher = Some(bstr_out(|p| info.Author(p))).filter(|s| !s.is_empty());
                item.install_date = bstr_out(|p| info.Date(p)).get(..10).map(str::to_string);
                item.detail("Description", bstr_out(|p| info.Description(p)));
            }
            if let Ok(principal) = def.Principal() {
                let user = bstr_out(|p| principal.UserId(p));
                if !user.is_empty() {
                    let is_service_account = user.starts_with("S-1-5-18")
                        || ["system", "local service", "network service"]
                            .iter()
                            .any(|s| user.to_ascii_lowercase().ends_with(s));
                    item.scope = if is_service_account { Scope::Machine } else { Scope::User };
                    item.user = crate::util::account_from_sid(&user).or(Some(user));
                }
            }
            if let Ok(actions) = def.Actions() {
                let mut count = 0i32;
                let _ = actions.Count(&mut count);
                for i in 1..=count {
                    let Ok(action) = actions.get_Item(i) else { continue };
                    let mut kind = Default::default();
                    if action.Type(&mut kind).is_err() || kind != TASK_ACTION_EXEC {
                        continue;
                    }
                    let Ok(exec) = action.cast::<IExecAction>() else { continue };
                    let exe = paths::expand(&bstr_out(|p| exec.Path(p)));
                    let args = bstr_out(|p| exec.Arguments(p));
                    item.detail("Action", format!("{exe} {args}").trim().to_string());
                    if item.executable.is_none() && !exe.is_empty() {
                        item.executable = Some(exe.trim_matches('"').to_string());
                    }
                    if item.install_location.is_none() && !exe.is_empty() && !paths::is_windows_path(&exe) {
                        item.install_location = paths::parent_dir(exe.trim_matches('"'));
                    }
                }
            }
        }

        if system {
            item.protection = Protection::System;
            item.hidden = true;
        }
        item.uninstall.push(UninstallMethod::Task { path });
        Ok(item)
    }
}
