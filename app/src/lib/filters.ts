import {
  PROTECTIONS,
  removalBlock,
  riskLevel,
  type Arch,
  type Item,
  type ItemKind,
  type Protection,
  type Scope,
  type SignatureStatus,
} from "./types";

export interface Filters {
  protections: Protection[];
  scope: "" | Scope;
  user: string;
  kind: "" | ItemKind;
  arch: "" | Arch;
  publisher: string;
  manager: string;
  flagged: "any" | "only" | "hide";
  removableOnly: boolean;
  signature: "" | SignatureStatus | "none";
  risk: "any" | "suspicious" | "untrusted" | "flagged" | "low" | "clean";
}

export const emptyFilters = (): Filters => ({
  protections: [...PROTECTIONS],
  scope: "",
  user: "",
  kind: "",
  arch: "",
  publisher: "",
  manager: "",
  flagged: "any",
  removableOnly: false,
  signature: "",
  risk: "any",
});

function matchesRisk(i: Item, risk: Filters["risk"]): boolean {
  if (risk === "any") return true;
  const level = riskLevel(i.risk);
  return risk === "flagged" ? level === "suspicious" || level === "untrusted" : level === risk;
}

export function matchesFilters(i: Item, f: Filters): boolean {
  return (
    f.protections.includes(i.protection) &&
    (!f.scope || i.scope === f.scope) &&
    (!f.user || (i.user ?? "") === f.user) &&
    (!f.kind || i.kind === f.kind) &&
    (!f.arch || i.arch === f.arch) &&
    (!f.publisher || (i.publisher ?? "") === f.publisher) &&
    (!f.manager || (i.manager ?? "") === f.manager) &&
    (f.flagged === "any" || (f.flagged === "only" ? i.hidden : !i.hidden)) &&
    (!f.removableOnly || removalBlock(i) === null) &&
    (!f.signature || (f.signature === "none" ? !i.signature : i.signature?.status === f.signature)) &&
    matchesRisk(i, f.risk)
  );
}

export function activeFilterCount(f: Filters): number {
  return (
    (f.protections.length < PROTECTIONS.length ? 1 : 0) +
    [f.scope, f.user, f.kind, f.arch, f.publisher, f.manager, f.signature].filter(Boolean).length +
    (f.flagged !== "any" ? 1 : 0) +
    (f.removableOnly ? 1 : 0) +
    (f.risk !== "any" ? 1 : 0)
  );
}
