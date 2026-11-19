import { readFileSync } from "node:fs";
import { join } from "node:path";

import { expect, type Page } from "@playwright/test";

export type Fixture = {
  tenant: string; password: string; approve: string; reject: string; expired: string;
  xss: string; auditor_view: string; csrf_target: string; critical: string; run: string;
  child_run: string; planner_run: string; xss_subject: string; keyboard: string; keyboard_action: string;
  connector: string; proposal: string; user_code: string; // C2
  coding_run: string; coding_denied: string; coding_ask: string; coding_ask_approval: string; second_run: string; // ADR-0039/40
};

export const fx: Fixture = JSON.parse(readFileSync(join(__dirname, ".fixture.json"), "utf8"));

/** Collect CSP violations and page errors so every test can assert there were none. */
export function watch(page: Page): string[] {
  const problems: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error" && /Content Security Policy|Refused to/i.test(m.text())) problems.push(m.text());
  });
  page.on("pageerror", (e) => problems.push(e.message));
  return problems;
}

/** Sign in. `view` pins the console view (ADR-0039): the specs written for today's layout use
 *  "technical"; the plain-English specs pass "simple" (the product default). */
export async function login(page: Page, user: string, view: "simple" | "technical" = "technical") {
  await page.context().addCookies([{ name: "agw_view", value: view, url: page.url().startsWith("http") ? new URL(page.url()).origin : (process.env.AGW_E2E_BASE_URL ?? "http://127.0.0.1:23000"), httpOnly: true, secure: true, sameSite: "Strict" }]);
  await page.goto("/login");
  await page.getByLabel("Tenant").fill(fx.tenant);
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(fx.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByTestId("whoami")).toContainText(user);
}

/** The CSRF token the server rendered into this page's forms (as a real form would send). */
export async function csrfOf(page: Page): Promise<string> {
  return (await page.locator('input[name="csrf"]').first().getAttribute("value")) ?? "";
}

/** Open the user menu (top bar) and choose an item: logout, density, timezone. */
export async function userMenu(page: Page, item: string | RegExp) {
  await page.getByRole("button", { name: /User menu for/ }).click();
  await page.getByRole("menuitem", { name: item }).or(page.getByRole("menuitemradio", { name: item })).first().click();
}

/** Approve through the confirmation dialog (Phase 9.5): open it, satisfy the CRITICAL
 *  type-to-confirm gate when present, then confirm. */
export async function confirmApprove(page: Page) {
  await page.getByRole("button", { name: "Approve exactly this action" }).click();
  const dialog = page.getByTestId("approve-dialog");
  await expect(dialog).toBeVisible();
  const code = dialog.getByTestId("confirm-code");
  if (await code.count()) await dialog.getByLabel(/to confirm/).fill(((await code.textContent()) ?? "").trim());
  await dialog.getByRole("button", { name: "Confirm approval" }).click();
}

/** C2: re-authenticate (step-up) on an admin page that shows the inline step-up card. */
export async function stepUp(page: Page) {
  const form = page.getByTestId("step-up-form");
  if (await form.count()) {
    await form.getByLabel(/Re-enter your password/).fill(fx.password);
    await form.getByRole("button", { name: "Re-authenticate" }).click();
  }
  await expect(page.getByTestId("step-up-ok")).toBeVisible();
}
