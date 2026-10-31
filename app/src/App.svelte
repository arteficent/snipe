<script lang="ts">
  import { getVersion } from "@tauri-apps/api/app";
  import { onMount } from "svelte";
  import * as api from "./lib/api";
  import DetailsPane from "./lib/DetailsPane.svelte";
  import FilterBar from "./lib/FilterBar.svelte";
  import HistoryDialog from "./lib/HistoryDialog.svelte";
  import ItemTable from "./lib/ItemTable.svelte";
  import UninstallDialog from "./lib/UninstallDialog.svelte";
  import { emptyFilters, matchesFilters, type Filters } from "./lib/filters";
  import { CATEGORIES, KIND_LABELS, inCategory, type Item, type ScanEvent, type Session, type SortKey } from "./lib/types";

  interface CollectorState {
    label: string;
    status: "running" | "done" | "failed" | "skipped";
    count: number;
    elapsedMs: number;
    error?: string;
  }

  let items = $state.raw<Item[]>([]);
  let collectors = $state<Record<string, CollectorState>>({});
  let scanning = $state(false);
  let fromCache = $state(false);
  let notice = $state<string | null>(null);
  let totalMs = $state<number | null>(null);
  let session = $state<Session>({ elevated: false, admin: false });
  let startingAdmin = $state(false);

  let category = $state("all");
  let search = $state("");
  let filters = $state<Filters>(emptyFilters());
  let selectedId = $state<string | null>(null);
  let sortKey = $state<SortKey>("name");
  let sortAsc = $state(true);

  let dialog = $state<{ item: Item; mode: "uninstall" | "force" | "threat" } | null>(null);
  let version = $state("");
  let showHistory = $state(false);

  const collator = new Intl.Collator(undefined, { sensitivity: "base", numeric: true });
  const PROTECTION_ORDER = { removable: 0, shared: 1, system: 2, locked: 3 };

  const categoryOf = (id: string) => CATEGORIES.find((c) => c.id === id) ?? CATEGORIES[0];

  const categoryItems = $derived.by(() => {
    const cat = categoryOf(category);
    return items.filter((i) => inCategory(i, cat));
  });

  const filtered = $derived(items.filter((i) => matchesFilters(i, filters)));

  const counts = $derived.by(() => {
    const result: Record<string, number> = {};
    for (const cat of CATEGORIES) {
      result[cat.id] = filtered.filter((i) => inCategory(i, cat)).length;
    }
    return result;
  });

  const rows = $derived.by(() => {
    const cat = categoryOf(category);
    const needle = search.trim().toLowerCase();
    const list = filtered.filter((i) => {
      if (!inCategory(i, cat)) return false;
      if (!needle) return true;
      return (
        i.name.toLowerCase().includes(needle) ||
        (i.publisher?.toLowerCase().includes(needle) ?? false) ||
        (i.version?.toLowerCase().includes(needle) ?? false) ||
        (i.user?.toLowerCase().includes(needle) ?? false) ||
        (i.installLocation?.toLowerCase().includes(needle) ?? false)
      );
    });
    const dir = sortAsc ? 1 : -1;
    return list.sort((a, b) => {
      let c: number;
      switch (sortKey) {
        case "sizeBytes":
          c = (a.sizeBytes ?? -1) - (b.sizeBytes ?? -1);
          break;
        case "risk":
          c = a.risk - b.risk;
          break;
        case "protection":
          c = PROTECTION_ORDER[a.protection] - PROTECTION_ORDER[b.protection];
          break;
        case "kind":
          c = collator.compare(KIND_LABELS[a.kind], KIND_LABELS[b.kind]);
          break;
        default:
          c = collator.compare(a[sortKey] ?? "", b[sortKey] ?? "");
      }
      return c * dir || collator.compare(a.name, b.name);
    });
  });

  const selected = $derived(selectedId ? (items.find((i) => i.id === selectedId) ?? null) : null);
  const skippedAdmin = $derived(Object.values(collectors).some((c) => c.status === "skipped"));

  let fresh: Item[] = [];

  function onEvent(e: ScanEvent) {
    switch (e.event) {
      case "started":
        fresh = [];
        collectors = Object.fromEntries(
          e.collectors.map((c) => [c.id, { label: c.label, status: "running" as const, count: 0, elapsedMs: 0 }]),
        );
        break;
      case "batch":
        fresh = fresh.concat(e.items);
        // Keep cached rows of collectors that haven't reported yet, replace the rest.
        if (fromCache) {
          const freshKinds = new Set(fresh.map((f) => f.kind));
          items = fresh.concat(items.filter((i) => !freshKinds.has(i.kind)));
        } else {
          items = fresh;
        }
        collectors[e.collector] = { ...collectors[e.collector], status: "done", count: e.items.length, elapsedMs: e.elapsedMs };
        break;
      case "failed":
        collectors[e.collector] = {
          ...collectors[e.collector],
          status: e.skipped ? "skipped" : "failed",
          error: e.error,
          elapsedMs: e.elapsedMs,
        };
        break;
      case "finished":
        items = fresh;
        fromCache = false;
        totalMs = e.elapsedMs;
        scanning = false;
        break;
    }
  }

  async function refresh() {
    if (scanning) return;
    scanning = true;
    notice = null;
    totalMs = null;
    collectors = {};
    try {
      await api.scan(onEvent);
    } catch (err) {
      notice = String(err);
      scanning = false;
    }
  }

  async function startAdmin() {
    startingAdmin = true;
    notice = null;
    try {
      session = await api.startAdmin();
      await refresh();
    } catch (e) {
      notice = String(e);
    }
    startingAdmin = false;
  }

  async function terminate(item: Item) {
    notice = null;
    try {
      await api.terminate(item.id);
      items = items.filter((i) => i.id !== item.id);
      selectedId = null;
      notice = `Ended ${item.name}.`;
    } catch (e) {
      notice = String(e);
    }
  }

  async function exportAs(format: "csv" | "json") {
    try {
      const path = await api.exportInventory(format);
      notice = `Exported to ${path}`;
    } catch (e) {
      notice = String(e);
    }
  }

  async function closeDialog(changed: boolean) {
    dialog = null;
    session = await api.session();
    if (changed) await refresh();
  }

  async function closeHistory() {
    showHistory = false;
    session = await api.session();
    await refresh();
  }

  function onsort(key: SortKey) {
    if (sortKey === key) sortAsc = !sortAsc;
    else {
      sortKey = key;
      sortAsc = key !== "sizeBytes" && key !== "installDate" && key !== "risk";
    }
  }

  onMount(async () => {
    getVersion().then((v) => (version = v)).catch(() => {});
    session = await api.session();
    const cached = await api.loadCache().catch(() => null);
    if (cached && cached.items.length > 0) {
      items = cached.items;
      fromCache = true;
    }
    await refresh();
  });
</script>

<div class="app">
  <nav class="sidebar">
    <div class="brand">Snipe {#if version}<span class="version">v{version}</span>{/if}</div>
    {#each CATEGORIES as cat}
      <button class="nav-item" class:active={category === cat.id} onclick={() => (category = cat.id)}>
        <span>{cat.label}</span>
        <span class="count">{counts[cat.id]}</span>
      </button>
    {/each}
  </nav>

  <main>
    <header class="toolbar">
      <input type="search" placeholder="Search name, publisher, version, user, path…" bind:value={search} />
      <div class="spacer"></div>
      {#if session.admin}
        <span class="badge admin" title="Privileged operations run in the elevated session">Administrator</span>
      {:else}
        <button onclick={startAdmin} disabled={startingAdmin} title="Scan Windows features, updates and other admin-only data; required for uninstalling">
          {startingAdmin ? "Waiting for UAC…" : "Admin session"}
        </button>
      {/if}
      <button onclick={() => (showHistory = true)}>History</button>
      <button onclick={() => exportAs("csv")}>Export CSV</button>
      <button onclick={() => exportAs("json")}>Export JSON</button>
      <button onclick={refresh} disabled={scanning}>{scanning ? "Scanning…" : "Refresh"}</button>
    </header>

    <FilterBar items={categoryItems} bind:filters />

    <div class="content">
      <ItemTable {rows} {selectedId} {sortKey} {sortAsc} onselect={(id) => (selectedId = id)} {onsort} />
      {#if selected}
        {#key selected.id}
          <DetailsPane
            item={selected}
            onuninstall={(forced) => (dialog = { item: selected!, mode: forced ? "force" : "uninstall" })}
            onthreat={() => (dialog = { item: selected!, mode: "threat" })}
            onterminate={() => terminate(selected!)}
          />
        {/key}
      {/if}
    </div>

    <footer class="status">
      <span>
        {rows.length} shown · {items.length} total{fromCache ? " (cached)" : ""}{totalMs != null
          ? ` · scanned in ${totalMs} ms`
          : ""}
      </span>
      {#if skippedAdmin && !session.admin}
        <span class="hint">Some sources need an admin session.</span>
      {/if}
      <span class="collectors">
        {#each Object.entries(collectors) as [id, c] (id)}
          <span class="chip {c.status}" title={c.error ?? `${c.count} items in ${c.elapsedMs} ms`}>
            {c.label}{c.status === "running"
              ? "…"
              : c.status === "failed"
                ? " ✕"
                : c.status === "skipped"
                  ? " (admin)"
                  : ` ${c.count}`}
          </span>
        {/each}
      </span>
      {#if notice}<span class="notice" title={notice}>{notice}</span>{/if}
    </footer>
  </main>
</div>

{#if dialog}
  <UninstallDialog item={dialog.item} mode={dialog.mode} onclose={closeDialog} />
{/if}
{#if showHistory}
  <HistoryDialog onclose={closeHistory} />
{/if}

<style>
  .app {
    display: flex;
    height: 100vh;
  }
  .sidebar {
    width: 210px;
    flex-shrink: 0;
    background: var(--bg-elevated);
    border-right: 1px solid var(--border);
    padding: 12px 8px;
    display: flex;
    flex-direction: column;
    gap: 2px;
    overflow-y: auto;
  }
  .brand {
    font-weight: 700;
    font-size: 18px;
    padding: 4px 10px 14px;
    color: var(--accent);
  }
  .version {
    font-size: 11px;
    font-weight: 400;
    color: var(--fg-muted);
  }
  .nav-item {
    display: flex;
    justify-content: space-between;
    background: none;
    border: none;
    border-radius: 6px;
    padding: 7px 10px;
    text-align: left;
    color: var(--fg);
  }
  .nav-item:hover {
    background: var(--bg-hover);
  }
  .nav-item.active {
    background: var(--accent-bg);
    font-weight: 600;
  }
  .count {
    color: var(--fg-muted);
    font-variant-numeric: tabular-nums;
  }
  main {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .toolbar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
  }
  .toolbar input[type="search"] {
    flex: 1;
    max-width: 440px;
  }
  .spacer {
    flex: 1;
  }
  .badge.admin {
    padding: 4px 10px;
    border-radius: 12px;
    background: var(--badge-locked);
    font-size: 12px;
    font-weight: 600;
  }
  .content {
    flex: 1;
    display: flex;
    min-height: 0;
  }
  .status {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 4px 12px;
    font-size: 12px;
    color: var(--fg-muted);
    border-top: 1px solid var(--border);
    background: var(--bg-elevated);
    white-space: nowrap;
    overflow: hidden;
  }
  .collectors {
    display: flex;
    gap: 6px;
    overflow: hidden;
    flex-shrink: 1;
  }
  .chip {
    padding: 1px 8px;
    border-radius: 10px;
    background: var(--bg-hover);
  }
  .chip.running {
    color: var(--accent);
  }
  .chip.failed {
    color: var(--danger);
  }
  .chip.skipped {
    opacity: 0.6;
  }
  .hint {
    color: var(--accent);
  }
  .notice {
    margin-left: auto;
    overflow: hidden;
    text-overflow: ellipsis;
    color: var(--fg);
  }
</style>
