import { expect, test } from "@playwright/test";

import { fx, login, watch } from "./helpers";

test("login: wrong password refused; session only in an httpOnly Secure SameSite=Strict cookie", async ({ page, context }) => {
  const problems = watch(page);
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/); // no session -> login
  await page.getByLabel("Tenant").fill(fx.tenant);
  await page.getByLabel("Username").fill("alice");
  await page.getByLabel("Password").fill("wrong-password-xx");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByTestId("login-error")).toContainText("Login failed");

  await login(page, "alice");
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  const cookies = await context.cookies();
  const session = cookies.find((c) => c.name === "__Host-agw_session");
  expect(session?.httpOnly).toBe(true);
  expect(session?.secure).toBe(true);
  expect(session?.sameSite).toBe("Strict");
  expect(await page.evaluate(() => document.cookie)).not.toContain("agw_session");
  expect(await page.evaluate(() => Object.keys(window.localStorage).length + Object.keys(window.sessionStorage).length)).toBe(0);
  const resp = await page.goto("/");
  const csp = resp?.headers()["content-security-policy"] ?? "";
  expect(csp).toContain("script-src 'self' 'nonce-");
  expect(csp).toContain("frame-ancestors 'none'");
  expect(csp).not.toContain("unsafe-inline");
  expect(problems).toEqual([]);

  await page.getByRole("button", { name: "Log out" }).click();
  await expect(page).toHaveURL(/\/login$/);
  await page.goto("/runs");
  await expect(page).toHaveURL(/\/login$/);
});
