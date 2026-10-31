<script lang="ts">
  import { defenderScan, openLocation } from "./api";
  import {
    KIND_LABELS,
    SIGNATURE_LABELS,
    canForce,
    canRemoveThreat,
    formatSize,
    methodLabel,
    removalBlock,
    riskLevel,
    type Item,
  } from "./types";

  interface Props {
    item: Item;
    onuninstall: (forced: boolean) => void;
    onthreat: () => void;
    onterminate: () => void;
  }

  let { item, onuninstall, onthreat, onterminate }: Props = $props();
  let error = $state<string | null>(null);
  let verdict = $state<string | null>(null);
  let scanning = $state(false);

  async function scanWithDefender() {
    scanning = true;
    verdict = null;
    error = null;
    try {
      verdict = await defenderScan(item.id);
    } catch (e) {
      error = String(e);
    }
    scanning = false;
  }

  const block = $derived(removalBlock(item));
  const isCache = $derived(item.kind === "cache");

  async function open(path: string) {
    error = null;
    try {
      await openLocation(path);
    } catch (e) {
      error = String(e);
    }
  }

  const facts = $derived(
    [
      ["Type", KIND_LABELS[item.kind]],
      ["Version", item.version],
      ["Publisher", item.publisher],
      ["Scope", item.scope === "user" ? "User" : "Machine"],
      ["User", item.user],
      ["Architecture", item.arch === "unknown" ? null : item.arch],
      ["Manager", item.manager],
      ["Size", formatSize(item.sizeBytes)],
      ["Installed", item.installDate],
      ["Protection", item.protection],
      ["System flagged", item.hidden ? "yes" : null],
    ].filter(([, v]) => v) as [string, string][],
  );
</script>

<aside class="details">
  <h2 title={item.name}>{item.name}</h2>

  <div class="actions">
    {#if item.kind === "process"}
      <button class="danger" disabled={item.protection === "locked"} onclick={onterminate}>End process</button>
    {:else}
      <button class="danger" disabled={block !== null} title={block ?? ""} onclick={() => onuninstall(false)}>
        {isCache ? "Clean…" : "Uninstall…"}
      </button>
      {#if canForce(item)}
        <button onclick={() => onuninstall(true)} title="Skip the uninstaller and remove what is left behind">
          Force remove…
        </button>
      {/if}
    {/if}
  </div>
  {#if block && item.kind !== "process"}<p class="note">{block}</p>{/if}

  {#if item.signature || item.executable}
    <h3>Security</h3>
    {#if item.risk >= 40}
      <div class="alert {riskLevel(item.risk)}">
        <strong>{riskLevel(item.risk) === "suspicious" ? "Suspicious" : "Untrusted"} · risk {item.risk}</strong>
        <ul>
          {#each item.riskReasons as r}<li>{r}</li>{/each}
        </ul>
      </div>
    {:else if item.riskReasons.length > 0}
      <ul class="reasons">
        {#each item.riskReasons as r}<li>{r}</li>{/each}
      </ul>
    {/if}
    <dl>
      {#if item.signature}
        <dt>Signature</dt>
        <dd>{SIGNATURE_LABELS[item.signature.status]}</dd>
        {#if item.signature.signer}<dt>Signed by</dt><dd>{item.signature.signer}</dd>{/if}
      {/if}
      {#if item.executable}<dt>Executable</dt><dd class="mono">{item.executable}</dd>{/if}
    </dl>
    <div class="actions spaced">
      {#if canRemoveThreat(item)}
        <button class="danger" onclick={onthreat} title="Stop it, remove its autostart entries and quarantine the file">
          Remove threat…
        </button>
      {/if}
      {#if item.executable}
        <button onclick={scanWithDefender} disabled={scanning}>{scanning ? "Scanning…" : "Scan with Defender"}</button>
      {/if}
    </div>
    {#if verdict}<p class="verdict">{verdict}</p>{/if}
    <p class="note">Risk is a heuristic based on signatures, location and autostart behaviour, not an antivirus verdict.</p>
  {/if}

  <dl>
    {#each facts as [label, value]}
      <dt>{label}</dt>
      <dd>{value}</dd>
    {/each}
  </dl>

  {#if item.installLocation}
    <h3>Location</h3>
    <div class="path">{item.installLocation}</div>
    <button onclick={() => open(item.installLocation!)}>Open in Explorer</button>
  {/if}

  {#if item.uninstall.length > 0}
    <h3>Removal methods</h3>
    <ul>
      {#each item.uninstall as m}
        <li class="mono">{methodLabel(m)}</li>
      {/each}
    </ul>
  {/if}

  {#if item.details.length > 0}
    <h3>Details</h3>
    <dl>
      {#each item.details as [label, value]}
        <dt>{label}</dt>
        <dd class="mono">{value}</dd>
      {/each}
    </dl>
  {/if}

  {#if error}<p class="error">{error}</p>{/if}
</aside>

<style>
  .details {
    width: 360px;
    flex-shrink: 0;
    border-left: 1px solid var(--border);
    padding: 16px;
    overflow-y: auto;
    background: var(--bg-elevated);
  }
  h2 {
    font-size: 16px;
    margin: 0 0 12px;
    word-break: break-word;
  }
  h3 {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--fg-muted);
    margin: 18px 0 6px;
  }
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 4px 12px;
    margin: 12px 0 0;
  }
  dt {
    color: var(--fg-muted);
  }
  dd {
    margin: 0;
    word-break: break-word;
  }
  .mono,
  .path {
    font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
    font-size: 12px;
    word-break: break-all;
  }
  .path {
    margin-bottom: 8px;
  }
  ul {
    margin: 0;
    padding-left: 18px;
  }
  li {
    margin-bottom: 4px;
  }
  .actions {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }
  .note {
    color: var(--fg-muted);
    font-size: 12px;
  }
  .spaced {
    margin-top: 10px;
  }
  .alert {
    border-radius: 6px;
    padding: 8px 10px;
    background: var(--badge-shared);
  }
  .alert.suspicious {
    background: var(--badge-locked);
  }
  .alert ul,
  .reasons {
    margin: 4px 0 0;
    font-size: 12px;
  }
  .verdict {
    font-weight: 600;
  }
  .error {
    color: var(--danger);
  }
</style>
