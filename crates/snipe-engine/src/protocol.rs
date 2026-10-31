//! Messages exchanged between the UI and the engine (directly or through the elevated broker).

use serde::{Deserialize, Serialize};
use snipe_core::{Item, RegPath};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectorInfo {
    pub id: String,
    pub label: String,
    pub requires_admin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ScanEvent {
    Started { collectors: Vec<CollectorInfo>, elevated: bool },
    Batch { collector: String, items: Vec<Item>, elapsed_ms: u64 },
    Failed { collector: String, error: String, elapsed_ms: u64, skipped: bool },
    Finished { total: usize, elapsed_ms: u64 },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecOptions {
    /// Index into `Item::uninstall`.
    pub method: usize,
    /// Prefer silent switches when the uninstaller supports them.
    pub silent: bool,
}

/// Requests carry item IDs only; paths and commands are always re-derived by the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Request {
    Ping,
    Scan,
    Plan { id: String },
    RestorePoint { description: String },
    Execute { id: String, options: ExecOptions },
    Leftovers { id: String, forced: bool },
    Clean { txn: String, ids: Vec<String> },
    History,
    Undo { txn: String },
    Terminate { id: String },
    /// Leftover-style removal plan for an untrusted executable and its persistence.
    Threat { id: String },
    /// On-demand Microsoft Defender scan of the item's executable.
    DefenderScan { id: String },
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Response {
    Event { event: ScanEvent },
    Ok { value: serde_json::Value },
    Err { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MethodInfo {
    pub index: usize,
    pub label: String,
    /// Runs in the standard-user context instead of the elevated broker.
    pub runs_unelevated: bool,
    /// Removal is recorded in a transaction and can be undone.
    pub undoable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub item: Item,
    pub blocked: Option<String>,
    pub warnings: Vec<String>,
    pub methods: Vec<MethodInfo>,
    pub processes: Vec<ProcInfo>,
    /// Leftover cleanup without running an uninstaller is possible.
    pub can_force: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecOutcome {
    pub success: bool,
    pub exit_code: Option<i64>,
    pub reboot_required: bool,
    pub still_present: bool,
    pub message: String,
    /// Transaction created when the method itself was a recorded removal.
    pub txn: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Target {
    File { path: String },
    Dir { path: String },
    RegKey { key: RegPath },
    RegValue { key: RegPath, name: String },
    Service { name: String },
    Task { path: String },
    EnvPath { key: RegPath, entry: String },
    /// Terminate every process running this image.
    Process { path: String },
}

impl Target {
    pub fn display(&self) -> String {
        match self {
            Target::File { path } | Target::Dir { path } => path.clone(),
            Target::RegKey { key } => key.to_string(),
            Target::RegValue { key, name } => format!("{key} → {}", if name.is_empty() { "(Default)" } else { name }),
            Target::Service { name } => format!("Service {name}"),
            Target::Task { path } => format!("Scheduled task {path}"),
            Target::EnvPath { key, entry } => format!("PATH entry {entry} ({key})"),
            Target::Process { path } => format!("Stop running instances of {path}"),
        }
    }

    pub fn id(&self) -> String {
        let text = serde_json::to_string(self).unwrap_or_default().to_ascii_lowercase();
        format!("{:016x}", snipe_core::fnv1a(text.bytes()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Leftover {
    pub id: String,
    pub target: Target,
    pub display: String,
    pub score: u8,
    pub reasons: Vec<String>,
    pub size_bytes: Option<u64>,
    pub preselected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeftoverReport {
    pub txn: String,
    pub leftovers: Vec<Leftover>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanReport {
    pub removed: usize,
    pub failed: Vec<(String, String)>,
    pub reboot_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxnSummary {
    pub id: String,
    pub created: u64,
    pub item_name: String,
    pub item_kind: String,
    pub found: usize,
    pub removed: usize,
    pub undone: bool,
    pub can_undo: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UndoReport {
    pub restored: usize,
    pub failed: Vec<String>,
}
