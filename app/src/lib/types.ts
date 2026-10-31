export type ItemKind =
  | "win32"
  | "msi"
  | "appx"
  | "feature"
  | "capability"
  | "update"
  | "driver"
  | "service"
  | "process"
  | "task"
  | "startup"
  | "package"
  | "module"
  | "sdk"
  | "runtime"
  | "cache";
export type Scope = "machine" | "user";
export type Arch = "x64" | "x86" | "arm64" | "neutral" | "unknown";
export type Protection = "removable" | "shared" | "system" | "locked";
export type SignatureStatus = "trusted" | "unsigned" | "untrusted" | "invalid" | "expired" | "unknown";

export interface Signature {
  status: SignatureStatus;
  signer: string | null;
}

export const SIGNATURE_LABELS: Record<SignatureStatus, string> = {
  trusted: "Trusted",
  unsigned: "Not signed",
  untrusted: "Untrusted / self-signed",
  invalid: "Invalid / tampered",
  expired: "Expired",
  unknown: "Could not verify",
};

export const RISK_SUSPICIOUS = 70;
export const RISK_UNTRUSTED = 40;

export function riskLevel(score: number): "suspicious" | "untrusted" | "low" | "clean" {
  if (score >= RISK_SUSPICIOUS) return "suspicious";
  if (score >= RISK_UNTRUSTED) return "untrusted";
  return score > 0 ? "low" : "clean";
}

export interface RegPath {
  key: string;
  wow32: boolean;
}

export type UninstallMethod =
  | { type: "command"; command: string; quiet: boolean }
  | { type: "msi"; productCode: string }
  | { type: "appx"; packageFullName: string }
  | { type: "service"; name: string }
  | { type: "driver"; inf: string }
  | { type: "feature"; name: string }
  | { type: "capability"; name: string }
  | { type: "update"; package: string }
  | { type: "task"; path: string }
  | { type: "registryValue"; key: RegPath; value: string }
  | { type: "packageManager"; manager: string; name: string; tool: string | null }
  | { type: "deletePath"; path: string }
  | { type: "cleanDir"; path: string };

export interface Item {
  id: string;
  kind: ItemKind;
  name: string;
  version: string | null;
  publisher: string | null;
  installLocation: string | null;
  installDate: string | null;
  sizeBytes: number | null;
  scope: Scope;
  user: string | null;
  arch: Arch;
  protection: Protection;
  hidden: boolean;
  manager: string | null;
  uninstall: UninstallMethod[];
  registry: RegPath | null;
  executable: string | null;
  signature: Signature | null;
  risk: number;
  riskReasons: string[];
  source: string;
  details: [string, string][];
}

export interface CollectorInfo {
  id: string;
  label: string;
  requiresAdmin: boolean;
}

export type ScanEvent =
  | { event: "started"; collectors: CollectorInfo[]; elevated: boolean }
  | { event: "batch"; collector: string; items: Item[]; elapsedMs: number }
  | { event: "failed"; collector: string; error: string; elapsedMs: number; skipped: boolean }
  | { event: "finished"; total: number; elapsedMs: number };

export interface Session {
  elevated: boolean;
  admin: boolean;
}

export interface MethodInfo {
  index: number;
  label: string;
  runsUnelevated: boolean;
  undoable: boolean;
}

export interface ProcInfo {
  pid: number;
  name: string;
  path: string;
}

export interface Plan {
  item: Item;
  blocked: string | null;
  warnings: string[];
  methods: MethodInfo[];
  processes: ProcInfo[];
  canForce: boolean;
}

export interface ExecOutcome {
  success: boolean;
  exitCode: number | null;
  rebootRequired: boolean;
  stillPresent: boolean;
  message: string;
  txn: string | null;
}

export interface Leftover {
  id: string;
  target: { type: string };
  display: string;
  score: number;
  reasons: string[];
  sizeBytes: number | null;
  preselected: boolean;
}

export interface LeftoverReport {
  txn: string;
  leftovers: Leftover[];
}

export interface CleanReport {
  removed: number;
  failed: [string, string][];
  rebootRequired: boolean;
}

export interface TxnSummary {
  id: string;
  created: number;
  itemName: string;
  itemKind: string;
  found: number;
  removed: number;
  undone: boolean;
  canUndo: boolean;
}

export interface UndoReport {
  restored: number;
  failed: string[];
}

export type SortKey =
  | "name"
  | "version"
  | "publisher"
  | "kind"
  | "scope"
  | "user"
  | "sizeBytes"
  | "installDate"
  | "protection"
  | "risk";

export const KIND_LABELS: Record<ItemKind, string> = {
  win32: "Program",
  msi: "MSI",
  appx: "Store app",
  feature: "Feature",
  capability: "Capability",
  update: "Update",
  driver: "Driver",
  service: "Service",
  process: "Process",
  task: "Task",
  startup: "Startup",
  package: "Package",
  module: "PS module",
  sdk: "SDK",
  runtime: "Runtime",
  cache: "Cache",
};

export const PROTECTIONS: Protection[] = ["removable", "shared", "system", "locked"];

export interface Category {
  id: string;
  label: string;
  kinds: ItemKind[] | null;
  minRisk?: number;
}

export const CATEGORIES: Category[] = [
  { id: "all", label: "Everything", kinds: null },
  { id: "threats", label: "Untrusted & suspicious", kinds: null, minRisk: RISK_UNTRUSTED },
  { id: "programs", label: "Programs", kinds: ["win32", "msi"] },
  { id: "appx", label: "Store & MSIX apps", kinds: ["appx"] },
  { id: "features", label: "Windows features", kinds: ["feature", "capability"] },
  { id: "updates", label: "Updates & packages", kinds: ["update"] },
  { id: "drivers", label: "Drivers", kinds: ["driver"] },
  { id: "services", label: "Services", kinds: ["service"] },
  { id: "tasks", label: "Scheduled tasks", kinds: ["task"] },
  { id: "startup", label: "Startup", kinds: ["startup"] },
  { id: "processes", label: "Processes", kinds: ["process"] },
  { id: "packages", label: "Package managers", kinds: ["package"] },
  { id: "modules", label: "PowerShell modules", kinds: ["module"] },
  { id: "dev", label: "SDKs & runtimes", kinds: ["sdk", "runtime"] },
  { id: "caches", label: "Caches", kinds: ["cache"] },
];

/** Mirrors `Item::removal_block` in snipe-core. */
export function removalBlock(item: Item): string | null {
  if (item.uninstall.length === 0) return "No removal method is known for this item.";
  if (item.protection === "locked") return "This item is critical to Windows and is never removed.";
  if (item.protection === "system" && !["feature", "capability", "update"].includes(item.kind))
    return "This is a Windows component; Snipe only removes it through supported mechanisms.";
  return null;
}

export function canForce(item: Item): boolean {
  return ["win32", "msi", "appx"].includes(item.kind) && item.protection !== "locked" && item.protection !== "system";
}

export function canRemoveThreat(item: Item): boolean {
  return item.risk >= RISK_UNTRUSTED && !!item.executable;
}

export function inCategory(item: Item, category: Category): boolean {
  return (!category.kinds || category.kinds.includes(item.kind)) && item.risk >= (category.minRisk ?? 0);
}

export function methodLabel(m: UninstallMethod): string {
  switch (m.type) {
    case "command":
      return `${m.quiet ? "Quiet uninstaller" : "Uninstaller"}: ${m.command}`;
    case "msi":
      return `Windows Installer: msiexec /x ${m.productCode}`;
    case "appx":
      return `Remove package ${m.packageFullName}`;
    case "service":
      return `Stop and delete service ${m.name}`;
    case "driver":
      return `Remove driver package ${m.inf}`;
    case "feature":
      return `Disable Windows feature ${m.name}`;
    case "capability":
      return `Remove capability ${m.name}`;
    case "update":
      return `Remove package ${m.package}`;
    case "task":
      return `Delete scheduled task ${m.path}`;
    case "registryValue":
      return `Delete registry value ${m.key.key}\\${m.value}`;
    case "packageManager":
      return `${m.manager} uninstall ${m.name}`;
    case "deletePath":
      return `Delete ${m.path}`;
    case "cleanDir":
      return `Empty ${m.path}`;
  }
}

export function formatSize(bytes: number | null): string {
  if (bytes == null) return "";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}
