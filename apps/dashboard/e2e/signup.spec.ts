import { expect, test } from "@playwright/test";

import { fx, watch } from "./helpers";

const PASSWORD = "correct horse battery staple";

async function fill(page: import("@playwright/test").Page, tenant: string, confirm = PASSWORD) {
  await page.goto("/signup");
  await page.getByLabel("Organization name").fill("Signup Test Co");
  await page.getByLabel("Tenant id").fill(tenant);
  await page.getByLabel("Username").fill("founder");
  await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await page.getByLabel("Confirm password").fill(confirm);
  await page.getByRole("button", { name: "Create account" }).click();
}

test("sign-up: login page links to it; a new tenant + admin is created and signed in", async ({ page, context }) => {
  const problems = watch(page);
  await page.goto("/login");
  await page.getByTestId("signup-link").click();
  await expect(page).toHaveURL(/\/signup$/);
  const tenant = `su-${Date.now().toString(36)}`;
  await fill(page, tenant);
  await expect(page.getByTestId("whoami")).toContainText("founder");
  await expect(page.getByTestId("onboarding")).toBeVisible(); // a brand-new tenant starts the checklist
  // The new account works for a normal sign-in afterwards.
  await context.clearCookies();
  await page.goto("/login");
  await page.getByLabel("Tenant").fill(tenant);
  await page.getByLabel("Username").fill("founder");
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByTestId("whoami")).toContainText("founder");
  expect(problems).toEqual([]);
});

test("sign-up: an existing tenant cannot be taken over; mismatched passwords are refused", async ({ page }) => {
  const problems = watch(page);
  await fill(page, fx.tenant);
  await expect(page.getByTestId("signup-error")).toContainText("already in use");
  await fill(page, `su-${Date.now().toString(36)}`, "something else entirely");
  await expect(page.getByTestId("signup-error")).toContainText("do not match");
  expect(problems).toEqual([]);
});
