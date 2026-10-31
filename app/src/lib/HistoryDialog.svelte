<script lang="ts">
  import { onMount } from "svelte";
  import * as api from "./api";
  import type { TxnSummary } from "./types";

  let { onclose }: { onclose: () => void } = $props();

  let entries = $state<TxnSummary[] | null>(null);
  let error = $state<string | null>(null);
  let message = $state<string | null>(null);
  let busy = $state<string | null>(null);

  async function load() {
    try {
      entries = await api.history();
    } catch (e) {
      error = String(e);
    }
  }

  async function undo(t: TxnSummary) {
    busy = t.id;
    message = null;
    error = null;
    try {
      const report = await api.undo(t.id);
      message = `Restored ${report.restored} item${report.restored === 1 ? "" : "s"} for ${t.itemName}.`;
      if (report.failed.length > 0) error = report.failed.join("\n");
      await load();
    } catch (e) {
      error = String(e);
    }
    busy = null;
  }

  onMount(load);
</script>

<div class="backdrop" role="presentation">
  <div class="dialog" role="dialog" aria-modal="true" aria-labelledby="hist-title">
    <header><h2 id="hist-title">History</h2></header>
    <div class="body">
      <p class="muted">
        Each removal is a transaction. Undo puts back quarantined files, registry data, tasks and services; it does not
        re-run an installer (use the System Restore point for that).
      </p>
      {#if message}<p class="ok">{message}</p>{/if}
      {#if error}<p class="error">{error}</p>{/if}
      {#if entries === null && !error}
        <p class="muted">Loading…</p>
      {:else if entries && entries.length === 0}
        <p class="muted">Nothing has been removed yet.</p>
      {:else if entries}
        <table>
          <thead>
            <tr><th>When</th><th>Item</th><th>Found</th><th>Removed</th><th></th></tr>
          </thead>
          <tbody>
            {#each entries as t (t.id)}
              <tr>
                <td>{new Date(t.created * 1000).toLocaleString()}</td>
                <td>{t.itemName}</td>
                <td>{t.found}</td>
                <td>{t.removed}</td>
                <td>
                  {#if t.undone}
                    <span class="muted">Undone</span>
                  {:else if t.canUndo}
                    <button disabled={busy !== null} onclick={() => undo(t)}>{busy === t.id ? "Undoing…" : "Undo"}</button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>
    <footer><button onclick={onclose}>Close</button></footer>
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.4);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10;
  }
  .dialog {
    width: min(760px, 92vw);
    max-height: 80vh;
    display: flex;
    flex-direction: column;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    box-shadow: 0 12px 40px rgba(0, 0, 0, 0.35);
  }
  header,
  footer {
    padding: 12px 18px;
  }
  header {
    border-bottom: 1px solid var(--border);
  }
  h2 {
    margin: 0;
    font-size: 16px;
  }
  .body {
    padding: 12px 18px;
    overflow-y: auto;
  }
  footer {
    border-top: 1px solid var(--border);
    display: flex;
    justify-content: flex-end;
  }
  table {
    width: 100%;
    border-collapse: collapse;
  }
  th,
  td {
    text-align: left;
    padding: 6px 8px;
    border-bottom: 1px solid var(--border-subtle);
  }
  th {
    color: var(--fg-muted);
    font-weight: 600;
    font-size: 12px;
  }
  .muted {
    color: var(--fg-muted);
  }
  .error {
    color: var(--danger);
    white-space: pre-line;
  }
  .ok {
    color: #2e7d32;
  }
</style>
