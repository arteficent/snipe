import { Channel, invoke } from "@tauri-apps/api/core";
import type {
  CleanReport,
  ExecOutcome,
  Item,
  LeftoverReport,
  Plan,
  ScanEvent,
  Session,
  TxnSummary,
  UndoReport,
} from "./types";

/** Starts a scan; events stream in through `onEvent` as each collector finishes. */
export async function scan(onEvent: (event: ScanEvent) => void): Promise<void> {
  const channel = new Channel<ScanEvent>();
  channel.onmessage = onEvent;
  await invoke("scan", { onEvent: channel });
}

export const loadCache = () => invoke<{ saved: number; items: Item[] } | null>("load_cache");
export const session = () => invoke<Session>("session");
export const startAdmin = () => invoke<Session>("start_admin");
export const plan = (id: string) => invoke<Plan>("plan", { id });
export const restorePoint = (description: string) => invoke<null>("restore_point", { description });
export const execute = (id: string, method: number, silent: boolean) =>
  invoke<ExecOutcome>("execute", { id, options: { method, silent } });
export const leftovers = (id: string, forced: boolean) => invoke<LeftoverReport>("leftovers", { id, forced });
export const clean = (txn: string, ids: string[]) => invoke<CleanReport>("clean", { txn, ids });
export const history = () => invoke<TxnSummary[]>("history");
export const undo = (txn: string) => invoke<UndoReport>("undo", { txn });
export const terminate = (id: string) => invoke<null>("terminate", { id });
export const threat = (id: string) => invoke<LeftoverReport>("threat", { id });
export const defenderScan = (id: string) => invoke<string>("defender_scan", { id });
export const exportInventory = (format: "csv" | "json") => invoke<string>("export_inventory", { format });
export const openLocation = (path: string) => invoke<void>("open_location", { path });
