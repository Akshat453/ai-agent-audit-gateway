// Phase 9: capture the dashboard screens from a running stack (compose profile "ui").
//   AGW_SHOT_URL=http://localhost:3000 AGW_SHOT_PASSWORD=... node scripts/screenshots.mjs
import { mkdirSync } from "node:fs";
import { join } from "node:path";

import { chromium } from "@playwright/test";

const BASE = process.env.AGW_SHOT_URL ?? "http://localhost:3000";
const PASSWORD = process.env.AGW_SHOT_PASSWORD;
const TENANT = process.env.AGW_SHOT_TENANT ?? "demo";
const OUT = process.env.AGW_SHOT_OUT ?? join(process.cwd(), "../../docs/gateway/screenshots");
if (!PASSWORD) throw new Error("AGW_SHOT_PASSWORD is required");
mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch();
async function session(user) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await ctx.newPage();
  await page.goto(`${BASE}/login`);
  await page.getByLabel("Tenant").fill(TENANT);
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByTestId("whoami").waitFor();
  return page;
}
async function shot(page, path, name) {
  await page.goto(`${BASE}${path}`);
  await page.waitForLoadState("networkidle");
  await page.screenshot({ path: join(OUT, `${name}.png`), fullPage: true });
  console.log(`${name}.png  <- ${path}`);
}

{
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 700 } });
  const page = await ctx.newPage();
  await shot(page, "/login", "01-login");
}
const admin = await session("adam");
await shot(admin, "/", "02-overview");
await shot(admin, "/runs", "03-runs");
const delegatedRun = await admin.locator("tr", { hasText: "yes" }).first().locator("a").first().getAttribute("href");
if (delegatedRun) await shot(admin, delegatedRun, "04-run-timeline-delegation");
await shot(admin, "/evidence", "07-evidence-explorer");
await shot(admin, "/epochs", "08-epochs-anchors");
await admin.goto(`${BASE}/verification`);
await admin.getByRole("button", { name: "Run verification now" }).click();
await admin.waitForTimeout(4000);
await shot(admin, "/verification", "09-verification");
await shot(admin, "/policies", "10-policies");
await shot(admin, "/incidents", "11-incidents");

const alice = await session("alice");
await shot(alice, "/approvals", "05-approval-center");
const found = await alice.locator("tbody tr").evaluateAll((trs) =>
  trs.map((tr) => ({ text: tr.innerText, href: tr.querySelector("a")?.getAttribute("href") ?? "" })),
);
const critical = found.find((r) => r.text.includes("CRITICAL"));
const email = found.find((r) => r.text.includes("send_email"));
if (email) await shot(alice, email.href, "06a-approval-detail");
if (critical) await shot(alice, critical.href, "06b-approval-critical-step-up");
await browser.close();
