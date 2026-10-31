use serde::Serialize;
use serde_json::Value;
use snipe_core::paths;
use snipe_engine::broker::BrokerClient;
use snipe_engine::{Engine, ExecOptions, Request, ScanEvent, cache, export, uninstall};
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager};

#[derive(Default)]
pub struct AppState {
    /// In-process engine running with the UI's own (normally standard-user) rights.
    engine: Mutex<Engine>,
    /// Elevated broker, started on demand through UAC.
    broker: Mutex<Option<BrokerClient>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    elevated: bool,
    admin: bool,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn self_elevated() -> bool {
    snipe_collectors::util::is_elevated()
}

fn broker_alive(state: &AppState) -> bool {
    lock(&state.broker).as_ref().is_some_and(|b| b.is_alive())
}

fn session_of(state: &AppState) -> Session {
    let elevated = self_elevated();
    Session { elevated, admin: elevated || broker_alive(state) }
}

/// Sends a request that needs administrator rights, starting the broker (UAC) if necessary.
fn admin_call(state: &AppState, request: Request, emit: &mut dyn FnMut(ScanEvent)) -> Result<Value, String> {
    if self_elevated() {
        return lock(&state.engine).handle(request, emit);
    }
    let mut guard = lock(&state.broker);
    if guard.as_ref().is_none_or(|b| !b.is_alive()) {
        *guard = Some(BrokerClient::launch()?);
    }
    guard.as_mut().expect("broker present").call(&request, emit)
}

fn local_call(state: &AppState, request: Request) -> Result<Value, String> {
    lock(&state.engine).handle(request, &mut |_| {})
}

async fn blocking<T: Send + 'static>(
    app: AppHandle,
    f: impl FnOnce(&AppState) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(move || f(&app.state::<AppState>()))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn load_cache() -> Result<Option<cache::Cached>, String> {
    Ok(tauri::async_runtime::spawn_blocking(cache::load).await.ok().flatten())
}

#[tauri::command]
pub fn session(app: AppHandle) -> Session {
    session_of(&app.state::<AppState>())
}

#[tauri::command]
pub async fn start_admin(app: AppHandle) -> Result<Session, String> {
    blocking(app, |state| {
        admin_call(state, Request::Ping, &mut |_| {})?;
        Ok(session_of(state))
    })
    .await
}

/// Scans (through the broker when an admin session is active) and streams results to the UI.
#[tauri::command]
pub async fn scan(app: AppHandle, on_event: Channel<ScanEvent>) -> Result<(), String> {
    blocking(app, move |state| {
        let mut emit = |event: ScanEvent| {
            let _ = on_event.send(event);
        };
        if broker_alive(state) {
            let mut items = Vec::new();
            admin_call(state, Request::Scan, &mut |event| {
                if let ScanEvent::Batch { items: batch, .. } = &event {
                    items.extend(batch.iter().cloned());
                }
                emit(event);
            })?;
            lock(&state.engine).set_inventory(items);
        } else {
            lock(&state.engine).scan(&mut emit);
        }
        let items = lock(&state.engine).items();
        let _ = cache::save(&items);
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn plan(app: AppHandle, id: String) -> Result<Value, String> {
    blocking(app, move |state| local_call(state, Request::Plan { id })).await
}

#[tauri::command]
pub async fn restore_point(app: AppHandle, description: String) -> Result<Value, String> {
    blocking(app, move |state| admin_call(state, Request::RestorePoint { description }, &mut |_| {})).await
}

/// Runs the selected removal method. User-scope uninstallers run without elevation.
#[tauri::command]
pub async fn execute(app: AppHandle, id: String, options: ExecOptions) -> Result<Value, String> {
    blocking(app, move |state| {
        // Make sure the admin session knows the item before anything is removed, so the
        // leftover scan afterwards can still resolve it.
        admin_call(state, Request::Plan { id: id.clone() }, &mut |_| {})?;
        let unelevated = {
            let engine = lock(&state.engine);
            let item = engine.get(&id).ok_or("Item not found; refresh and try again.")?;
            let method = item.uninstall.get(options.method).ok_or("unknown removal method")?;
            uninstall::runs_unelevated(item, method)
        };
        let request = Request::Execute { id, options };
        if unelevated && !self_elevated() {
            local_call(state, request)
        } else {
            admin_call(state, request, &mut |_| {})
        }
    })
    .await
}

#[tauri::command]
pub async fn leftovers(app: AppHandle, id: String, forced: bool) -> Result<Value, String> {
    blocking(app, move |state| admin_call(state, Request::Leftovers { id, forced }, &mut |_| {})).await
}

#[tauri::command]
pub async fn clean(app: AppHandle, txn: String, ids: Vec<String>) -> Result<Value, String> {
    blocking(app, move |state| admin_call(state, Request::Clean { txn, ids }, &mut |_| {})).await
}

#[tauri::command]
pub async fn history(app: AppHandle) -> Result<Value, String> {
    blocking(app, |state| admin_call(state, Request::History, &mut |_| {})).await
}

#[tauri::command]
pub async fn undo(app: AppHandle, txn: String) -> Result<Value, String> {
    blocking(app, move |state| admin_call(state, Request::Undo { txn }, &mut |_| {})).await
}

#[tauri::command]
pub async fn threat(app: AppHandle, id: String) -> Result<Value, String> {
    blocking(app, move |state| admin_call(state, Request::Threat { id }, &mut |_| {})).await
}

#[tauri::command]
pub async fn defender_scan(app: AppHandle, id: String) -> Result<Value, String> {
    blocking(app, move |state| local_call(state, Request::DefenderScan { id })).await
}

#[tauri::command]
pub async fn terminate(app: AppHandle, id: String) -> Result<Value, String> {
    blocking(app, move |state| {
        if broker_alive(state) {
            admin_call(state, Request::Terminate { id }, &mut |_| {})
        } else {
            local_call(state, Request::Terminate { id }).map_err(|e| {
                if e.contains("Access is denied") || e.contains("cannot open process") {
                    format!("{e}. Start an admin session to manage this process.")
                } else {
                    e
                }
            })
        }
    })
    .await
}

fn explorer() -> std::path::PathBuf {
    Path::new(paths::windows_dir()).join("explorer.exe")
}

/// Writes the current inventory to Documents and reveals the file.
#[tauri::command]
pub async fn export_inventory(app: AppHandle, format: String) -> Result<String, String> {
    blocking(app, move |state| {
        let mut items = lock(&state.engine).items();
        items.sort_by_key(|i| i.name.to_lowercase());
        let (text, ext) = match format.as_str() {
            "csv" => (export::to_csv(&items), "csv"),
            "json" => (export::to_json(&items), "json"),
            _ => return Err("unsupported format".into()),
        };
        let docs = std::env::var_os("USERPROFILE")
            .map(|p| Path::new(&p).join("Documents"))
            .ok_or("USERPROFILE not set")?;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = docs.join(format!("snipe-inventory-{stamp}.{ext}"));
        std::fs::write(&path, text).map_err(|e| e.to_string())?;
        let shown = path.to_string_lossy().into_owned();
        let _ = Command::new(explorer()).raw_arg(format!("/select,\"{shown}\"")).spawn();
        Ok(shown)
    })
    .await
}

/// Opens an existing local file or folder in Explorer.
#[tauri::command]
pub fn open_location(path: String) -> Result<(), String> {
    let p = Path::new(&path);
    // Only absolute local paths; `"` is invalid in Windows paths and would break quoting.
    if !p.is_absolute() || path.starts_with(r"\\") || path.contains('"') {
        return Err("invalid path".into());
    }
    let meta = std::fs::metadata(p).map_err(|e| e.to_string())?;
    let arg = if meta.is_dir() { format!("\"{path}\"") } else { format!("/select,\"{path}\"") };
    Command::new(explorer()).raw_arg(arg).spawn().map(|_| ()).map_err(|e| e.to_string())
}
