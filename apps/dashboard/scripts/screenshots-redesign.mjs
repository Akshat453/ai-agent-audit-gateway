// Phase 9.5: capture the redesigned console (light + dark) from a running stack (compose
// profile "ui"), and FAIL if the browser reports any CSP violation or page error.
//   AGW_SHOT_PASSWORD=... node scripts/screenshots-redesign.mjs
import { mkdirSync } from "node:fs";
import { join } from "node:path";

import { chromium } from "@playwright/test";

const BASE = process.env.AGW_SHOT_URL ?? "http://localhost:3000";
const PASSWORD = process.env.AGW_SHOT_PASSWORD;
const TENANT = process.env.AGW_SHOT_TENANT ?? "demo";
const OUT = process.env.AGW_SHOT_OUT ?? join(process.cwd(), "../../docs/gateway/screenshots/redesign/after");
if (!PASSWORD) throw new Error("AGW_SHOT_PASSWORD is required");
mkdirSync(OUT, { recursive: true });

const problems = [];
const browser = await chromium.launch();
const host = new URL(BASE).hostname;

async function context(theme) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 960 } });
  await ctx.addCookies([{ name: "agw_theme", value: theme, domain: host, path: "/", httpOnly: true, secure: true, sameSite: "Strict" }]);
  return ctx;
}
function watch(page, tag) {
  page.on("console", (m) => {
    if (m.type() === "error" && /Content Security Policy|Refused to/i.test(m.text())) problems.push(`${tag}: ${m.text()}`);
  });
  page.on("pageerror", (e) => problems.push(`${tag}: ${e.message}`));
}
async function session(user, theme) {
  const ctx = await context(theme);
  const page = await ctx.newPage();
  watch(page, `${user}/${theme}`);
  await page.goto(`${BASE}/login`);
  await page.getByLabel("Tenant").fill(TENANT);
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByTestId("whoami").waitFor();
  return page;
}
async function shot(page, path, name, { full = true, after } = {}) {
  await page.goto(`${BASE}${path}`);
  await page.waitForLoadState("networkidle");
  if (after) await after(page);
  await page.waitForTimeout(500);
  await page.screenshot({ path: join(OUT, `${name}.png`), fullPage: full, animations: "disabled" });
  console.log(`${name}.png  <- ${path}`);
}

for (const theme of ["light", "dark"]) {
  {
    const ctx = await context(theme);
    const page = await ctx.newPage();
    watch(page, `login/${theme}`);
    await shot(page, "/login", `01-login-${theme}`, { full: false });
    await ctx.close();
  }
  const adam = await session("adam", theme);
  await shot(adam, "/", `02-overview-${theme}`);
  // first action that has an anchored event, else any
  const runHref = await adam.evaluate(async () => {
    const r = await fetch("/runs");
    const html = await r.text();
    const m = html.match(/href="(\/runs\/[0-9a-f-]{36})"/);
    return m ? m[1] : null;
  });
  if (runHref) {
    await adam.goto(`${BASE}${runHref}`);
    const actionHref = await adam.locator('a[href^="/actions/"]').first().getAttribute("href");
    if (actionHref) {
      await shot(adam, actionHref, `05-action-evidence-timeline-${theme}`);
      const eventHref = await adam.locator('ol[aria-label="Evidence timeline"] a[href^="/events/"]').first().getAttribute("href");
      if (eventHref) await shot(adam, eventHref, `06-event-proof-explorer-${theme}`, { after: (p) => p.getByTestId("proof-explorer").waitFor() });
    }
  }
  await shot(adam, "/approvals?state=ALL", `03a-approvals-${theme}`);
  const alice = await session("alice", theme);
  await shot(alice, "/approvals", `03b-approvals-pending-${theme}`);
  const firstRow = alice.locator("tbody tr[data-row]").first();
  if (await firstRow.count()) {
    const id = await firstRow.getAttribute("data-row");
    await shot(alice, `/approvals?sel=${id}`, `03c-approvals-split-panel-${theme}`);
    await shot(alice, `/approvals/${id}`, `04a-approval-detail-${theme}`);
    await alice.getByRole("button", { name: "Approve exactly this action" }).click();
    await alice.getByTestId("approve-dialog").waitFor();
    await alice.waitForTimeout(300);
    await alice.screenshot({ path: join(OUT, `04b-approval-confirm-dialog-${theme}.png`) });
    console.log(`04b-approval-confirm-dialog-${theme}.png`);
    await alice.keyboard.press("Escape");
  }
  const critical = alice.locator("tbody tr[data-row]", { hasText: "CRITICAL" }).first();
  await alice.goto(`${BASE}/approvals`);
  if (await critical.count()) {
    const id = await critical.getAttribute("data-row");
    await shot(alice, `/approvals/${id}`, `04c-approval-critical-${theme}`);
  }
  await alice.keyboard.press("Control+k");
  await alice.waitForTimeout(400);
  await alice.screenshot({ path: join(OUT, `07-command-palette-${theme}.png`) });
  console.log(`07-command-palette-${theme}.png`);
  await alice.keyboard.press("Escape");
  await alice.goto(`${BASE}/approvals`);
  await alice.getByRole("button", { name: "Help for this page" }).click();
  await alice.waitForTimeout(400);
  await alice.screenshot({ path: join(OUT, `08-help-drawer-${theme}.png`) });
  console.log(`08-help-drawer-${theme}.png`);
  await shot(adam, "/runs", `09-legacy-runs-in-new-shell-${theme}`, { full: false });
}
// responsive: approvals list + detail at laptop (1024) and tablet (768) widths, light theme
for (const width of [1024, 768]) {
  const ctx = await browser.newContext({ viewport: { width, height: 900 } });
  await ctx.addCookies([{ name: "agw_theme", value: "light", domain: host, path: "/", httpOnly: true, secure: true, sameSite: "Strict" }]);
  const page = await ctx.newPage();
  watch(page, `alice/${width}`);
  await page.goto(`${BASE}/login`);
  await page.getByLabel("Tenant").fill(TENANT);
  await page.getByLabel("Username").fill("alice");
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL(`${BASE}/`);
  await shot(page, "/approvals?state=ALL", `10-approvals-${width}px`, { full: false });
  const id = await page.locator("tbody tr[data-row]").first().getAttribute("data-row");
  if (id) await shot(page, `/approvals/${id}`, `10-approval-detail-${width}px`, { full: false });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  if (overflow > 1) problems.push(`approval detail at ${width}px scrolls horizontally by ${overflow}px`);
  await ctx.close();
}
await browser.close();
if (problems.length) {
  console.error(`\n${problems.length} CSP violation(s) / page error(s):\n${problems.join("\n")}`);
  process.exit(1);
}
console.log("no CSP violations, no page errors");
