<script lang="ts">
  import { activeFilterCount, emptyFilters, type Filters } from "./filters";
  import { KIND_LABELS, PROTECTIONS, SIGNATURE_LABELS, riskLevel, type Item, type ItemKind } from "./types";

  let { items, filters = $bindable() }: { items: Item[]; filters: Filters } = $props();

  const collator = new Intl.Collator(undefined, { sensitivity: "base", numeric: true });

  function distinct(values: (string | null)[]): string[] {
    return [...new Set(values.filter((v): v is string => !!v))].sort(collator.compare);
  }

  const users = $derived(distinct(items.map((i) => i.user)));
  const kinds = $derived(distinct(items.map((i) => i.kind)) as ItemKind[]);
  const arches = $derived(distinct(items.map((i) => i.arch)));
  const publishers = $derived(distinct(items.map((i) => i.publisher)));
  const managers = $derived(distinct(items.map((i) => i.manager)));
  const protectionCounts = $derived(
    Object.fromEntries(PROTECTIONS.map((p) => [p, items.filter((i) => i.protection === p).length])),
  );
  const active = $derived(activeFilterCount(filters));
  const riskCounts = $derived.by(() => {
    let suspicious = 0;
    let untrusted = 0;
    for (const i of items) {
      const level = riskLevel(i.risk);
      if (level === "suspicious") suspicious++;
      else if (level === "untrusted") untrusted++;
    }
    return { suspicious, untrusted, flagged: suspicious + untrusted };
  });

  function toggleProtection(p: (typeof PROTECTIONS)[number]) {
    filters.protections = filters.protections.includes(p)
      ? filters.protections.filter((x) => x !== p)
      : [...filters.protections, p];
  }
</script>

<div class="filters">
  <div class="group" role="group" aria-label="Protection">
    {#each PROTECTIONS as p}
      <button
        class="chip {p}"
        class:off={!filters.protections.includes(p)}
        aria-pressed={filters.protections.includes(p)}
        onclick={() => toggleProtection(p)}
        title="Show {p} items"
      >
        {p} <span class="n">{protectionCounts[p]}</span>
      </button>
    {/each}
  </div>

  <label>
    Risk
    <select bind:value={filters.risk}>
      <option value="any">Any</option>
      <option value="flagged">Untrusted or suspicious ({riskCounts.flagged})</option>
      <option value="suspicious">Suspicious ({riskCounts.suspicious})</option>
      <option value="untrusted">Untrusted ({riskCounts.untrusted})</option>
      <option value="low">Low</option>
      <option value="clean">Clean</option>
    </select>
  </label>

  <label>
    Signature
    <select bind:value={filters.signature}>
      <option value="">All</option>
      {#each Object.entries(SIGNATURE_LABELS) as [value, label]}<option {value}>{label}</option>{/each}
      <option value="none">Not checked</option>
    </select>
  </label>

  <label>
    Scope
    <select bind:value={filters.scope}>
      <option value="">All</option>
      <option value="machine">Machine</option>
      <option value="user">User</option>
    </select>
  </label>

  <label>
    User
    <select bind:value={filters.user}>
      <option value="">All</option>
      {#each users as u}<option value={u}>{u}</option>{/each}
    </select>
  </label>

  <label>
    Type
    <select bind:value={filters.kind}>
      <option value="">All</option>
      {#each kinds as k}<option value={k}>{KIND_LABELS[k]}</option>{/each}
    </select>
  </label>

  <label>
    Arch
    <select bind:value={filters.arch}>
      <option value="">All</option>
      {#each arches as a}<option value={a}>{a}</option>{/each}
    </select>
  </label>

  <label>
    Publisher
    <select bind:value={filters.publisher} class="wide">
      <option value="">All</option>
      {#each publishers as p}<option value={p}>{p}</option>{/each}
    </select>
  </label>

  {#if managers.length > 0}
    <label>
      Manager
      <select bind:value={filters.manager}>
        <option value="">All</option>
        {#each managers as m}<option value={m}>{m}</option>{/each}
      </select>
    </label>
  {/if}

  <label>
    System flag
    <select bind:value={filters.flagged}>
      <option value="any">Any</option>
      <option value="hide">Not flagged</option>
      <option value="only">Only flagged</option>
    </select>
  </label>

  <label class="check">
    <input type="checkbox" bind:checked={filters.removableOnly} />
    Removable only
  </label>

  {#if active > 0}
    <button class="clear" onclick={() => (filters = emptyFilters())}>Clear filters ({active})</button>
  {/if}
</div>

<style>
  .filters {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px 14px;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-elevated);
    font-size: 12px;
  }
  .group {
    display: flex;
    gap: 4px;
  }
  label {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--fg-muted);
  }
  select {
    font: inherit;
    color: var(--fg);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 5px;
    padding: 3px 6px;
    max-width: 150px;
  }
  select.wide {
    max-width: 200px;
  }
  .check {
    user-select: none;
  }
  .chip {
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 12px;
    text-transform: capitalize;
    border: 1px solid transparent;
    background: var(--badge-removable);
  }
  .chip.shared {
    background: var(--badge-shared);
  }
  .chip.system {
    background: var(--badge-system);
  }
  .chip.locked {
    background: var(--badge-locked);
  }
  .chip.off {
    background: none;
    border-color: var(--border);
    color: var(--fg-muted);
    text-decoration: line-through;
  }
  .n {
    opacity: 0.7;
    margin-left: 2px;
  }
  .clear {
    padding: 3px 10px;
    font-size: 12px;
  }
</style>
