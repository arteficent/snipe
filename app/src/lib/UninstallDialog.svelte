<script lang="ts">
  import { onMount } from "svelte";
  import * as api from "./api";
  import {
    canForce,
    formatSize,
    type CleanReport,
    type ExecOutcome,
    type Item,
    type Leftover,
    type Plan,
  } from "./types";

  interface Props {
    item: Item;
    mode: "uninstall" | "force" | "threat";
    onclose: (changed: boolean) => void;
  }

  let { item, mode, onclose }: Props = $props();
  const forced = $derived(mode === "force");
  const threat = $derived(mode === "threat");

  type Step = "loading" | "plan" | "running" | "review" | "done";
  let step = $state<Step>("loading");
  let plan = $state<Plan | null>(null);
  let method = $state(0);
  let silent = $state(true);
  let restorePoint = $state(true);
  let progress = $state("");
  let notes = $state<string[]>([]);
  let error = $state<string | null>(null);
  let outcome = $state<ExecOutcome | null>(null);
  let txn = $state<string | null>(null);
  let leftovers = $state<Leftover[]>([]);
  let selected = $state<Record<string, boolean>>({});
  let showLow = $state(false);
  let cleanReport = $state<CleanReport | null>(null);
  let changed = false;

  const tracesApply = $derived(canForce(item));
  const visibleLeftovers = $derived(showLow ? leftovers : leftovers.filter((l) => l.score >= 50));
  const selectedCount = $derived(leftovers.filter((l) => selected[l.id]).length);
  const selectedSize = $derived(
    leftovers.filter((l) => selected[l.id]).reduce((sum, l) => sum + (l.sizeBytes ?? 0), 0),
  );

  onMount(() => {
    api
      .plan(item.id)
      .then((p) => {
        plan = p;
        method = p.methods[0]?.index ?? 0;
        step = "plan";
      })
      .catch((e) => {
        error = String(e);
        step = "done";
      });
  });

  async function scanLeftovers() {
    progress = threat ? "Finding the file, running instances and autostart entries…" : "Scanning for leftovers…";
    const report = threat ? await api.threat(item.id) : await api.leftovers(item.id, forced);
    txn = report.txn;
    leftovers = report.leftovers;
    selected = Object.fromEntries(report.leftovers.map((l) => [l.id, l.preselected]));
    step = leftovers.length > 0 ? "review" : "done";
  }

  async function run() {
    step = "running";
    error = null;
    try {
      if (restorePoint) {
        progress = "Creating a System Restore point…";
        try {
          await api.restorePoint(`Snipe: remove ${item.name}`);
        } catch (e) {
          notes.push(`Restore point skipped: ${e}`);
        }
      }
      if (!forced && !threat) {
        progress = "Running the uninstaller… (follow any prompts it shows)";
        outcome = await api.execute(item.id, method, silent);
        changed = true;
        if (!outcome.success) {
          error = outcome.message;
          step = "done";
          return;
        }
      }
      if (tracesApply || threat) {
        await scanLeftovers();
      } else {
        step = "done";
      }
    } catch (e) {
      error = String(e);
      step = "done";
    }
  }

  async function scanAnyway() {
    step = "running";
    error = null;
    try {
      await scanLeftovers();
    } catch (e) {
      error = String(e);
      step = "done";
    }
  }

  async function cleanSelected() {
    if (!txn) return;
    step = "running";
    progress = "Backing up and removing leftovers…";
    try {
      cleanReport = await api.clean(
        txn,
        leftovers.filter((l) => selected[l.id]).map((l) => l.id),
      );
      changed = true;
    } catch (e) {
      error = String(e);
    }
    step = "done";
  }

  function setAll(value: boolean) {
    selected = Object.fromEntries(leftovers.map((l) => [l.id, value && (showLow || l.score >= 50)]));
  }

  function leftoverText(id: string) {
    return leftovers.find((l) => l.id === id)?.display ?? id;
  }
</script>

<div class="backdrop" role="presentation">
  <div class="dialog" role="dialog" aria-modal="true" aria-labelledby="dlg-title">
    <header>
      <h2 id="dlg-title">
        {threat ? "Remove threat" : forced ? "Force remove" : item.kind === "cache" ? "Clean" : "Uninstall"}
        {item.name}
      </h2>
    </header>

    <div class="body">
      {#if step === "loading"}
        <p class="muted">Preparing…</p>
      {:else if step === "plan" && plan && threat}
        <p class="warning">Risk {item.risk}: {item.riskReasons.join("; ")}.</p>
        <p>
          Snipe will stop running instances, remove the startup entries, scheduled tasks and services that launch
          <span class="mono">{item.executable}</span>, and move the file to quarantine. You review the list first;
          everything can be restored from History.
        </p>
        <p class="muted small">
          This is a heuristic, not an antivirus verdict. If in doubt, use "Scan with Defender" first.
        </p>
        <label class="opt"><input type="checkbox" bind:checked={restorePoint} /> Create a System Restore point first</label>
        <p class="muted small">Administrator permission will be requested.</p>
      {:else if step === "plan" && plan}
        {#if plan.blocked && !forced}
          <p class="error">{plan.blocked}</p>
        {/if}
        {#each plan.warnings as w}<p class="warning">{w}</p>{/each}
        {#if forced}
          <p>
            The uninstaller will not be run. Snipe scans for the files, folders and registry entries this program
            left behind; you review them before anything is removed.
          </p>
        {:else if !plan.blocked}
          <h3>Removal method</h3>
          {#each plan.methods as m}
            <label class="method">
              <input type="radio" name="method" value={m.index} bind:group={method} />
              <span class="mono">{m.label}</span>
              {#if m.runsUnelevated}<span class="tag">runs as you</span>{/if}
              {#if m.undoable}<span class="tag">undoable</span>{/if}
            </label>
          {/each}
          <label class="opt"><input type="checkbox" bind:checked={silent} /> Prefer silent mode when supported</label>
        {/if}
        {#if !plan.blocked || forced}
          <label class="opt"><input type="checkbox" bind:checked={restorePoint} /> Create a System Restore point first</label>
        {/if}
        {#if plan.processes.length > 0}
          <h3>Running processes that will be closed</h3>
          <ul>
            {#each plan.processes as p}<li class="mono">{p.name} (PID {p.pid})</li>{/each}
          </ul>
        {/if}
        <p class="muted small">Administrator permission will be requested if needed.</p>
      {:else if step === "running"}
        <div class="spinner" aria-hidden="true"></div>
        <p>{progress}</p>
      {:else if step === "review"}
        {#if outcome}<p class="ok">{outcome.message}</p>{/if}
        <p>
          Found {leftovers.length} leftover{leftovers.length === 1 ? "" : "s"}. High-confidence entries are
          pre-selected. Everything removed is backed up and can be restored from History.
        </p>
        <div class="row">
          <button onclick={() => setAll(true)}>Select all</button>
          <button onclick={() => setAll(false)}>Select none</button>
          <label class="opt"><input type="checkbox" bind:checked={showLow} /> Show low-confidence matches</label>
        </div>
        <div class="list">
          {#each visibleLeftovers as l (l.id)}
            <label class="leftover">
              <input type="checkbox" bind:checked={selected[l.id]} />
              <span class="score" class:high={l.score >= 80} class:mid={l.score >= 50 && l.score < 80}>{l.score}</span>
              <span class="what">
                <span class="mono">{l.display}</span>
                <span class="why">{l.reasons.join(" · ")}{l.sizeBytes ? ` · ${formatSize(l.sizeBytes)}` : ""}</span>
              </span>
            </label>
          {/each}
        </div>
      {:else if step === "done"}
        {#if error}<p class="error">{error}</p>{/if}
        {#if outcome && !error}<p class="ok">{outcome.message}</p>{/if}
        {#if outcome?.stillPresent && outcome.success}
          <p class="warning">The item is still registered. It may finish after a restart, or the uninstaller was cancelled.</p>
        {/if}
        {#if outcome?.txn}<p class="muted">This removal can be undone from History.</p>{/if}
        {#if cleanReport}
          <p class="ok">Removed {cleanReport.removed} leftover{cleanReport.removed === 1 ? "" : "s"}.</p>
          {#if cleanReport.failed.length > 0}
            <p class="warning">Could not remove:</p>
            <ul>
              {#each cleanReport.failed as [id, why]}<li class="mono">{leftoverText(id)} — {why}</li>{/each}
            </ul>
          {/if}
          <p class="muted">Backups are kept for 30 days; use History to undo.</p>
        {:else if txn && leftovers.length === 0 && !error}
          <p class="ok">No leftovers found.</p>
        {/if}
        {#if outcome?.rebootRequired || cleanReport?.rebootRequired}
          <p class="warning">Restart Windows to finish removing everything.</p>
        {/if}
        {#each notes as n}<p class="muted">{n}</p>{/each}
      {/if}
    </div>

    <footer>
      {#if step === "plan" && plan}
        <button onclick={() => onclose(false)}>Cancel</button>
        <button class="danger" disabled={!!plan.blocked && mode === "uninstall"} onclick={run}>
          {threat ? "Review removal" : forced ? "Scan for leftovers" : item.kind === "cache" ? "Clean" : "Uninstall"}
        </button>
      {:else if step === "review"}
        <button onclick={() => { step = "done"; }}>Skip</button>
        <button class="danger" disabled={selectedCount === 0} onclick={cleanSelected}>
          Remove selected ({selectedCount}{selectedSize ? `, ${formatSize(selectedSize)}` : ""})
        </button>
      {:else if step === "done"}
        {#if error && tracesApply && !txn && outcome}
          <button onclick={scanAnyway}>Scan for leftovers anyway</button>
        {/if}
        <button onclick={() => onclose(changed)}>Close</button>
      {/if}
    </footer>
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
    width: min(820px, 92vw);
    max-height: 86vh;
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
    word-break: break-word;
  }
  h3 {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--fg-muted);
    margin: 14px 0 6px;
  }
  .body {
    padding: 12px 18px;
    overflow-y: auto;
    flex: 1;
  }
  footer {
    border-top: 1px solid var(--border);
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }
  .method,
  .opt {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 6px 0;
  }
  .tag {
    font-size: 11px;
    padding: 1px 6px;
    border-radius: 8px;
    background: var(--bg-hover);
    color: var(--fg-muted);
  }
  .row {
    display: flex;
    gap: 8px;
    align-items: center;
    margin-bottom: 8px;
  }
  .list {
    border: 1px solid var(--border);
    border-radius: 6px;
    max-height: 46vh;
    overflow-y: auto;
  }
  .leftover {
    display: flex;
    gap: 10px;
    align-items: flex-start;
    padding: 6px 10px;
    border-bottom: 1px solid var(--border-subtle);
  }
  .score {
    min-width: 30px;
    text-align: center;
    border-radius: 8px;
    font-size: 11px;
    padding: 1px 4px;
    background: var(--bg-hover);
  }
  .score.high {
    background: var(--badge-removable);
  }
  .score.mid {
    background: var(--badge-shared);
  }
  .what {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .why {
    font-size: 11px;
    color: var(--fg-muted);
  }
  .mono {
    font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
    font-size: 12px;
    word-break: break-all;
  }
  .muted {
    color: var(--fg-muted);
  }
  .small {
    font-size: 12px;
  }
  .error {
    color: var(--danger);
  }
  .warning {
    color: #b26a00;
  }
  .ok {
    color: #2e7d32;
  }
  .spinner {
    width: 28px;
    height: 28px;
    border: 3px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.9s linear infinite;
    margin: 12px 0;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>
