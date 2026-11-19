#!/usr/bin/env node
// Console field inventory, generated FROM THE CODE (plain-English console, ADR-0039).
//
// For every routed page it reads the page file and every component it imports (recursively,
// "@/components/..." only, UI primitives and the shell excluded) and lists the technical items
// the JSX renders: table columns (<th>, DataTable `header:`), field labels (<dt>), card and
// section titles, headings, summaries, badges (StatusBadge / RiskBadge / Badge), ids and hashes
// (HashChip and its `label`), links (href prefixes), labelled regions (aria-label) and test hooks
// (data-testid / data-check).
//
//   node scripts/inventory.mjs            -> docs/gateway/console-field-inventory.md + e2e/inventory.json
//
// The browser test (e2e/inventory.spec.ts) then proves every item that rendered before the
// plain-English layer still renders in Technical view.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const REPO = join(ROOT, "..", "..");

export const PAGES = [
  ["Overview", "/", "app/page.tsx"],
  ["Runs", "/runs", "app/runs/page.tsx"],
  ["Run detail", "/runs/[id]", "app/runs/[id]/page.tsx"],
  ["Action detail", "/actions/[id]", "app/actions/[id]/page.tsx"],
  ["Approvals", "/approvals", "app/approvals/page.tsx"],
  ["Approval detail", "/approvals/[id]", "app/approvals/[id]/page.tsx"],
  ["Events (evidence explorer)", "/evidence", "app/evidence/page.tsx"],
  ["Event detail", "/events/[id]", "app/events/[id]/page.tsx"],
  ["Epochs & anchors", "/epochs", "app/epochs/page.tsx"],
  ["Verification", "/verification", "app/verification/page.tsx"],
  ["Policies", "/policies", "app/policies/page.tsx"],
  ["Incidents", "/incidents", "app/incidents/page.tsx"],
  ["Integrations", "/integrations", "app/integrations/page.tsx"],
  ["Integration detail", "/integrations/[id]", "app/integrations/[id]/page.tsx"],
  ["Add integration", "/integrations/new", "app/integrations/new/page.tsx"],
  ["Repositories", "/repos", "app/repos/page.tsx"],
  ["People", "/people", "app/people/page.tsx"],
  ["Enroll a device", "/enroll", "app/enroll/page.tsx"],
];

const SKIP = /^@\/components\/(ui\/|shell\/|icons)/;
const clean = (s) => s.replace(/\s+/g, " ").replace(/&apos;/g, "'").trim();
const useful = (s) => s.length > 1 && !/^[\s·:,()→—\-–|/]+$/.test(s);

function imports(src) {
  return [...src.matchAll(/from "(@\/components\/[^"]+)"/g)].map((m) => m[1]).filter((p) => !SKIP.test(p));
}

function resolve(spec) {
  const base = join(ROOT, spec.replace(/^@\//, ""));
  for (const ext of [".tsx", ".ts", "/index.tsx"]) if (existsSync(base + ext)) return base + ext;
  return null;
}

function extract(src) {
  const items = [];
  const add = (kind, text) => {
    const t = clean(text);
    if (useful(t) && !items.some((i) => i.kind === kind && i.text === t)) items.push({ kind, text: t });
  };
  for (const m of src.matchAll(/<th\b[^>]*>([^<{]+)/g)) add("column", m[1]);
  for (const m of src.matchAll(/\bheader:\s*"([^"]+)"/g)) add("column", m[1]);
  for (const m of src.matchAll(/<dt\b[^>]*>([^<{]+)/g)) add("field", m[1]);
  for (const m of src.matchAll(/\btitle="([^"]+)"/g)) add("section", m[1]);
  for (const m of src.matchAll(/<h[1-4]\b[^>]*>([^<{]+)/g)) add("heading", m[1]);
  for (const m of src.matchAll(/<summary\b[^>]*>([^<{]+)/g)) add("section", m[1]);
  for (const m of src.matchAll(/<(StatusBadge|RiskBadge|Badge)\b[^>]*(?:value|level)=\{?"?([^"}\s]+)/g)) add("badge", `${m[1]} ${m[2]}`);
  for (const m of src.matchAll(/<HashChip\b[^>]*?label="([^"]+)"/g)) add("id/hash", m[1]);
  for (const m of src.matchAll(/aria-label="([^"]+)"/g)) add("region", m[1]);
  for (const m of src.matchAll(/data-testid="([^"]+)"/g)) add("test hook", m[1]);
  for (const m of src.matchAll(/data-check="([^"]+)"/g)) add("check", m[1]);
  for (const m of src.matchAll(/href=\{?[`"](\/[a-z][a-z/_-]*)/g)) add("link", m[1]);
  return items;
}

function walk(file, seen = new Set()) {
  if (seen.has(file)) return [];
  seen.add(file);
  const src = readFileSync(file, "utf8");
  const out = [{ file: relative(ROOT, file), items: extract(src) }];
  for (const spec of imports(src)) {
    const f = resolve(spec);
    if (f) out.push(...walk(f, seen));
  }
  return out;
}

export function inventory() {
  return PAGES.map(([name, route, file]) => ({ name, route, sources: walk(join(ROOT, file)) }));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const inv = inventory();
  writeFileSync(join(ROOT, "e2e", "inventory.json"), JSON.stringify(inv, null, 1) + "\n");
  const lines = [
    "# Console field inventory",
    "",
    "Generated from the dashboard code by `node apps/dashboard/scripts/inventory.mjs`; do not edit by hand.",
    "It lists every technical item each page renders: columns, fields, section titles, headings,",
    "badges, ids/hashes, links, labelled regions and test hooks, per source file (the page and the",
    "components it imports).",
    "",
    "Contract (plain-English console, ADR-0039): nothing in this list is removed. Each item is",
    "visible inline, under **Technical details**, or in **Technical view**. `e2e/inventory.spec.ts`",
    "walks every page in Technical view and asserts that every item that rendered before the change",
    "(`e2e/inventory.baseline.json`, captured on the pre-change console) still renders.",
    "",
  ];
  for (const p of inv) {
    lines.push(`## ${p.name} \`${p.route}\``, "");
    for (const s of p.sources) {
      if (!s.items.length) continue;
      lines.push(`**${s.file}**`, "");
      const byKind = new Map();
      for (const i of s.items) byKind.set(i.kind, [...(byKind.get(i.kind) ?? []), i.text]);
      for (const [kind, texts] of byKind) lines.push(`- ${kind}: ${texts.map((x) => `\`${x}\``).join(", ")}`);
      lines.push("");
    }
  }
  writeFileSync(join(REPO, "docs", "gateway", "console-field-inventory.md"), lines.join("\n"));
  console.log(`inventory: ${inv.length} pages, ${inv.reduce((n, p) => n + p.sources.reduce((m, s) => m + s.items.length, 0), 0)} items`);
}
