<script lang="ts">
  import { KIND_LABELS, formatSize, riskLevel, type Item, type SortKey } from "./types";

  interface Props {
    rows: Item[];
    selectedId: string | null;
    sortKey: SortKey;
    sortAsc: boolean;
    onselect: (id: string) => void;
    onsort: (key: SortKey) => void;
  }

  let { rows, selectedId, sortKey, sortAsc, onselect, onsort }: Props = $props();

  const ROW_HEIGHT = 32;
  const OVERSCAN = 10;

  const columns: { key: SortKey; label: string; align?: "right" }[] = [
    { key: "name", label: "Name" },
    { key: "version", label: "Version" },
    { key: "publisher", label: "Publisher" },
    { key: "kind", label: "Type" },
    { key: "scope", label: "Scope" },
    { key: "user", label: "User" },
    { key: "sizeBytes", label: "Size", align: "right" },
    { key: "installDate", label: "Installed" },
    { key: "protection", label: "Protection" },
    { key: "risk", label: "Risk", align: "right" },
  ];

  let viewport: HTMLDivElement;
  let scrollTop = $state(0);
  let viewportHeight = $state(0);

  const start = $derived(Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN));
  const end = $derived(Math.min(rows.length, Math.ceil((scrollTop + viewportHeight) / ROW_HEIGHT) + OVERSCAN));
  const visible = $derived(rows.slice(start, end));

  function onkeydown(e: KeyboardEvent) {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    if (rows.length === 0) return;
    const current = rows.findIndex((r) => r.id === selectedId);
    const next = Math.min(rows.length - 1, Math.max(0, current + (e.key === "ArrowDown" ? 1 : -1)));
    onselect(rows[next].id);
    const top = next * ROW_HEIGHT;
    if (top < viewport.scrollTop) viewport.scrollTop = top;
    else if (top + ROW_HEIGHT > viewport.scrollTop + viewportHeight)
      viewport.scrollTop = top + ROW_HEIGHT - viewportHeight;
  }
</script>

<div class="table">
  <div class="row header">
    {#each columns as col}
      <button class="cell" class:right={col.align === "right"} onclick={() => onsort(col.key)}>
        {col.label}
        {#if sortKey === col.key}<span class="arrow">{sortAsc ? "▲" : "▼"}</span>{/if}
      </button>
    {/each}
  </div>

  <div
    class="viewport"
    role="listbox"
    tabindex="0"
    aria-label="Installed items"
    bind:this={viewport}
    bind:clientHeight={viewportHeight}
    onscroll={() => (scrollTop = viewport.scrollTop)}
    {onkeydown}
  >
    <div class="spacer" style:height="{rows.length * ROW_HEIGHT}px">
      <div class="window" style:transform="translateY({start * ROW_HEIGHT}px)">
        {#each visible as item}
          <div
            class="row"
            class:selected={item.id === selectedId}
            class:dim={item.hidden}
            role="option"
            aria-selected={item.id === selectedId}
            tabindex="-1"
            onclick={() => onselect(item.id)}
            onkeydown={() => {}}
          >
            <span class="cell name" title={item.name}>{item.name}</span>
            <span class="cell" title={item.version ?? ""}>{item.version ?? ""}</span>
            <span class="cell" title={item.publisher ?? ""}>{item.publisher ?? ""}</span>
            <span class="cell">{KIND_LABELS[item.kind]}</span>
            <span class="cell">{item.scope === "user" ? "User" : "Machine"}</span>
            <span class="cell" title={item.user ?? ""}>{item.user ?? ""}</span>
            <span class="cell right">{formatSize(item.sizeBytes)}</span>
            <span class="cell">{item.installDate ?? ""}</span>
            <span class="cell"><span class="badge {item.protection}">{item.protection}</span></span>
            <span class="cell right">
              {#if item.risk > 0}
                <span class="risk {riskLevel(item.risk)}" title={item.riskReasons.join("\n")}>{item.risk}</span>
              {:else if item.signature?.status === "trusted"}
                <span class="signed" title={`Signed by ${item.signature.signer ?? "a trusted publisher"}`}>✓</span>
              {/if}
            </span>
          </div>
        {/each}
      </div>
    </div>
    {#if rows.length === 0}
      <div class="empty">No items match.</div>
    {/if}
  </div>
</div>

<style>
  .table {
    display: flex;
    flex-direction: column;
    min-height: 0;
    flex: 1;
  }
  .row {
    display: grid;
    grid-template-columns: minmax(220px, 3fr) minmax(90px, 1fr) minmax(130px, 2fr) 90px 76px minmax(110px, 1.2fr) 86px 96px 104px 60px;
    align-items: center;
    height: 32px;
    padding: 0 8px;
    border-bottom: 1px solid var(--border-subtle);
    cursor: default;
  }
  .header {
    background: var(--bg-elevated);
    border-bottom: 1px solid var(--border);
    font-weight: 600;
    font-size: 12px;
    color: var(--fg-muted);
  }
  .header .cell {
    background: none;
    border: none;
    color: inherit;
    font: inherit;
    text-align: left;
    cursor: pointer;
    height: 100%;
  }
  .header .cell:hover {
    color: var(--fg);
  }
  .arrow {
    font-size: 9px;
    margin-left: 4px;
  }
  .cell {
    padding: 0 8px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .right {
    text-align: right !important;
  }
  .name {
    font-weight: 500;
  }
  .viewport {
    flex: 1;
    overflow-y: auto;
    position: relative;
    outline: none;
  }
  .spacer {
    position: relative;
  }
  .window {
    position: absolute;
    inset: 0 0 auto 0;
    will-change: transform;
  }
  .window .row:hover {
    background: var(--bg-hover);
  }
  .window .row.selected {
    background: var(--accent-bg);
  }
  .viewport:focus-visible .row.selected {
    outline: 1px solid var(--accent);
    outline-offset: -1px;
  }
  .dim {
    color: var(--fg-muted);
  }
  .empty {
    position: absolute;
    inset: 40px 0 auto 0;
    text-align: center;
    color: var(--fg-muted);
  }
  .badge {
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 10px;
    text-transform: capitalize;
    background: var(--badge-removable);
  }
  .badge.shared {
    background: var(--badge-shared);
  }
  .badge.system {
    background: var(--badge-system);
  }
  .badge.locked {
    background: var(--badge-locked);
  }
  .risk {
    font-size: 11px;
    font-weight: 600;
    padding: 2px 7px;
    border-radius: 10px;
    background: var(--bg-hover);
  }
  .risk.untrusted {
    background: var(--badge-shared);
  }
  .risk.suspicious {
    background: var(--danger);
    color: #fff;
  }
  .signed {
    color: #2e7d32;
  }
</style>
