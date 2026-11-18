// Phase 9.5: gzipped JS actually loaded per route (first load), measured in a real browser
// against a running stack. Flags routes over the 300 KB budget (ADR-0033 §4).
//   AGW_SHOT_PASSWORD=... node scripts/bundle-report.mjs
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

import { chromium } from "@playwright/test";

const BASE = process.env.AGW_SHOT_URL ?? "http://localhost:3000";
const PASSWORD = process.env.AGW_SHOT_PASSWORD;
const BUDGET = 300 * 1024;
if (!PASSWORD) throw new Error("AGW_SHOT_PASSWORD is required");

const browser = await chromium.launch();
async function measure(path, storageState) {
  // a new context per route = empty HTTP cache = first-load cost
  const ctx = await browser.newContext(storageState ? { storageState } : {});
  const page = await ctx.newPage();
  const scripts = new Map();
  page.on("response", async (resp) => {
    const url = resp.url();
    if (resp.request().resourceType() === "script" && url.startsWith(BASE)) {
      try { scripts.set(url, await resp.body()); } catch { /* redirected */ }
    }
  });
  const r = await page.goto(`${BASE}${path}`, { waitUntil: "networkidle" });
  if (path !== "/login" && page.url().endsWith("/login")) throw new Error(`${path}: not signed in`);
  await ctx.close();
  let raw = 0, gz = 0;
  for (const b of scripts.values()) { raw += b.length; gz += gzipSync(b, { level: 9 }).length; }
  return { path, scripts: scripts.size, raw, gz, status: r?.status() };
}
const rows = [await measure("/login")];
const ctx = await browser.newContext();
const page = await ctx.newPage();
await page.goto(`${BASE}/login`);
await page.getByLabel("Tenant").fill("demo");
await page.getByLabel("Username").fill("adam");
await page.getByLabel("Password").fill(PASSWORD);
await page.getByRole("button", { name: "Sign in" }).click();
await page.getByTestId("whoami").waitFor();
const state = await ctx.storageState();
const approval = await page.evaluate(async () => (await (await fetch("/approvals?state=ALL")).text()).match(/\/approvals\/([0-9a-f-]{36})/)?.[1]);
const run = await page.evaluate(async () => (await (await fetch("/runs")).text()).match(/\/runs\/([0-9a-f-]{36})/)?.[1]);
await page.goto(`${BASE}/runs/${run}`);
const action = (await page.locator('a[href^="/actions/"]').first().getAttribute("href")) ?? "";
await page.goto(`${BASE}${action}`);
const event = (await page.locator('ol[aria-label="Evidence timeline"] a[href^="/events/"]').first().getAttribute("href")) ?? "";
for (const p of ["/", "/approvals", `/approvals/${approval}`, action, event, "/runs", "/evidence", "/epochs", "/verification", "/policies", "/incidents"]) {
  rows.push(await measure(p, state));
}
await browser.close();
const label = (p) => p.replace(/[0-9a-f-]{36}/, "[id]");
const lines = ["| Route | JS files | JS raw (KB) | JS gzip (KB) | Budget 300 KB |", "|---|---:|---:|---:|---|"];
for (const r of rows) lines.push(`| \`${label(r.path)}\` | ${r.scripts} | ${(r.raw / 1024).toFixed(1)} | ${(r.gz / 1024).toFixed(1)} | ${r.gz > BUDGET ? "**OVER**" : "ok"} |`);
const out = lines.join("\n");
console.log(out);
writeFileSync(join(process.cwd(), "../../docs/gateway/screenshots/redesign/bundle-report.md"), `# Bundle report (gzipped first-load JS per route)\n\nMeasured by \`apps/dashboard/scripts/bundle-report.mjs\` in Chromium against the production build (compose profile "ui"). Each script the page loaded, gzip level 9.\n\n${out}\n`);
process.exit(rows.some((r) => r.gz > BUDGET) ? 1 : 0);
