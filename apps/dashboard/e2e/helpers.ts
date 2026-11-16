import { readFileSync } from "node:fs";
import { join } from "node:path";

import { expect, type Page } from "@playwright/test";

export type Fixture = {
  tenant: string; password: string; approve: string; reject: string; expired: string;
  xss: string; auditor_view: string; csrf_target: string; critical: string; run: string;
  child_run: string; planner_run: string; xss_subject: string;
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

export async function login(page: Page, user: string) {
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
