import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

import { expect, test, type Page } from "@playwright/test";

import { fx, login } from "./helpers";

// Field-inventory contract (plain-English console, ADR-0039): every technical item a page
// rendered BEFORE the plain-English layer still renders in Technical view.
//
// AGW_INVENTORY_CAPTURE=1 records e2e/inventory.baseline.json (run once on the pre-change
// console); otherwise the test compares the current console in Technical view to it.
// Ids, hashes and numbers are normalised, so a fresh seed compares equal.

type Inv = { name: string; route: string; sources: { file: string; items: { kind: string; text: string }[] }[] }[];
type Snapshot = { texts: string[]; markers: string[] };

const HERE = __dirname;
const INV: Inv = JSON.parse(readFileSync(join(HERE, "inventory.json"), "utf8"));
const BASELINE = join(HERE, "inventory.baseline.json");
const CAPTURE = process.env.AGW_INVENTORY_CAPTURE === "1";
const TEXT_KINDS = new Set(["column", "field", "section", "heading"]);

function candidates(route: string): string[] {
  const page = INV.find((p) => p.route === route);
  return [...new Set((page?.sources ?? []).flatMap((s) => s.items.filter((i) => TEXT_KINDS.has(i.kind)).map((i) => i.text)))];
}

async function snapshot(page: Page, route: string): Promise<Snapshot> {
  return page.evaluate((cands) => {
    const norm = (s: string) => s
      .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, "<uuid>")
      .replace(/\b(0x)?[0-9a-f]{8,}\b/gi, "<hex>")
      .replace(/\d+/g, "<n>")
      .replace(/\s+/g, " ")
      .trim();
    const main = document.querySelector("main") ?? document.body;
    const text = (main.textContent ?? "").replace(/\s+/g, " ");
    const texts = cands.filter((c) => text.includes(c));
    const markers = new Set<string>();
    main.querySelectorAll<HTMLElement>("[data-testid]").forEach((e) => markers.add(`testid:${norm(e.dataset.testid ?? "")}`));
    main.querySelectorAll<HTMLElement>("[data-check]").forEach((e) => markers.add(`check:${e.dataset.check}`));
    main.querySelectorAll<HTMLElement>("[data-status]").forEach((e) => markers.add(`status:${e.dataset.status}`));
    main.querySelectorAll<HTMLAnchorElement>("a[href]").forEach((a) => {
      const h = a.getAttribute("href") ?? "";
      if (h.startsWith("/")) markers.add(`link:${norm(h.split("?")[0] ?? h)}`);
    });
    main.querySelectorAll<HTMLElement>("table[aria-label], section[aria-label], nav[aria-label], ol[aria-label], ul[aria-label], aside[aria-label], form[aria-label]")
      .forEach((e) => markers.add(`region:${norm(e.getAttribute("aria-label") ?? "")}`));
    main.querySelectorAll<HTMLElement>("[aria-label]").forEach((e) => {
      const l = e.getAttribute("aria-label") ?? "";
      // ids and hashes: "action <uuid>", "event hash <hex>", "run <uuid>: show full value"
      if (/[0-9a-f]{8}-|[0-9a-f]{16,}/i.test(l)) markers.add(`id:${norm(l)}`);
    });
    main.querySelectorAll("th").forEach((th) => markers.add(`column:${norm(th.textContent ?? "")}`));
    main.querySelectorAll("dt").forEach((dt) => markers.add(`field:${norm(dt.textContent ?? "")}`));
    return { texts, markers: [...markers].filter((m) => !m.endsWith(":")).sort() };
  }, candidates(route));
}

type Visit = { key: string; route: string; url: string | (() => string); user: "adam" | "alice" };

const VISITS: Visit[] = [
  { key: "overview", route: "/", url: "/", user: "adam" },
  { key: "runs", route: "/runs", url: "/runs", user: "adam" },
  { key: "run", route: "/runs/[id]", url: () => `/runs/${fx.run}`, user: "adam" },
  { key: "coding-run", route: "/runs/[id]", url: () => `/runs/${fx.coding_run}`, user: "adam" },
  { key: "action", route: "/actions/[id]", url: () => `/actions/${fx.keyboard_action}`, user: "adam" },
  { key: "coding-action", route: "/actions/[id]", url: () => `/actions/${fx.coding_denied}`, user: "adam" },
  { key: "approvals", route: "/approvals", url: "/approvals?state=ALL", user: "adam" },
  { key: "approvals-panel", route: "/approvals", url: () => `/approvals?state=ALL&sel=${fx.keyboard}`, user: "adam" },
  { key: "approval-critical", route: "/approvals/[id]", url: () => `/approvals/${fx.critical}`, user: "alice" },
  { key: "approval-coding", route: "/approvals/[id]", url: () => `/approvals/${fx.coding_ask_approval}`, user: "adam" },
  { key: "evidence", route: "/evidence", url: "/evidence", user: "adam" },
  { key: "epochs", route: "/epochs", url: "/epochs", user: "adam" },
  { key: "verification", route: "/verification", url: "/verification", user: "adam" },
  { key: "policies", route: "/policies", url: "/policies", user: "adam" },
  { key: "incidents", route: "/incidents", url: "/incidents", user: "adam" },
  { key: "integrations", route: "/integrations", url: "/integrations", user: "adam" },
  { key: "integration", route: "/integrations/[id]", url: () => `/integrations/${fx.connector}`, user: "adam" },
  { key: "integration-new", route: "/integrations/new", url: "/integrations/new?type=github", user: "adam" },
  { key: "repos", route: "/repos", url: "/repos", user: "adam" },
  { key: "people", route: "/people", url: "/people", user: "adam" },
  { key: "enroll", route: "/enroll", url: "/enroll", user: "adam" },
  { key: "enroll-code", route: "/enroll", url: () => `/enroll?code=${fx.user_code}`, user: "adam" },
];

test("field inventory: every technical item that rendered before still renders in Technical view", async ({ page, context, baseURL }) => {
  test.setTimeout(300_000);
  await context.addCookies([{ name: "agw_view", value: "technical", url: baseURL ?? "http://localhost:23000", httpOnly: true, secure: true, sameSite: "Strict" }]);
  const result: Record<string, Snapshot> = {};
  let who: string | null = null;
  const visit = async (v: Visit, url: string) => {
    if (who !== v.user) {
      await login(page, v.user);
      who = v.user;
    }
    await page.goto(url);
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(700); // stay under the per-session API rate limit
    result[v.key] = await snapshot(page, v.route);
  };
  for (const v of VISITS) await visit(v, typeof v.url === "string" ? v.url : v.url());
  // An event page, reached from the action's evidence timeline.
  await page.goto(`/actions/${fx.coding_denied}`);
  const ev = await page.locator('ol[aria-label="Evidence timeline"] a[href^="/events/"]').first().getAttribute("href");
  expect(ev).toBeTruthy();
  await visit({ key: "event", route: "/events/[id]", url: ev ?? "", user: "adam" }, ev ?? "/");

  // The policies baseline was captured while the session was rate-limited (the page showed its
  // error state), so assert today's policies content explicitly in Technical view.
  await page.goto("/policies");
  for (const title of ['Policy "default"', "Risk policies"]) await expect(page.getByRole("heading", { name: title })).toBeVisible();
  await expect(page.getByText(/^v2 · /)).toBeVisible();

  if (CAPTURE) {
    writeFileSync(BASELINE, JSON.stringify(result, null, 1) + "\n");
    return;
  }
  expect(existsSync(BASELINE), "baseline missing: run once with AGW_INVENTORY_CAPTURE=1 on the pre-change console").toBe(true);
  const base: Record<string, Snapshot> = JSON.parse(readFileSync(BASELINE, "utf8"));
  const missing: string[] = [];
  for (const [key, b] of Object.entries(base)) {
    const now = result[key];
    if (!now) { missing.push(`${key}: page not visited`); continue; }
    for (const t of b.texts) if (!now.texts.includes(t)) missing.push(`${key}: text "${t}"`);
    for (const m of b.markers) if (!now.markers.includes(m)) missing.push(`${key}: ${m}`);
  }
  expect(missing).toEqual([]);
});
