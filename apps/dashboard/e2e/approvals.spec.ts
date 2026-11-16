import { expect, test } from "@playwright/test";

import { fx, login, watch } from "./helpers";

test("approve flow: exact action shown, approve echoes digest + nonce, action authorized", async ({ page }) => {
  const problems = watch(page);
  await login(page, "alice");
  await page.goto("/approvals");
  await page.getByRole("link", { name: fx.approve.slice(0, 13) }).click();
  await expect(page.getByRole("heading", { name: /send_email@1.0.0/ })).toBeVisible();
  await expect(page.getByLabel("arguments")).toContainText("approve me");
  await expect(page.getByTestId("countdown")).toContainText("expires in");
  await page.getByRole("button", { name: "Approve exactly this action" }).click();
  await expect(page.getByRole("status")).toContainText("Approved");
  await expect(page.getByText("CONSUMED").first()).toBeVisible(); // single-use: consumed by the authorization
  await expect(page.getByRole("button", { name: "Approve exactly this action" })).toHaveCount(0);
  expect(problems).toEqual([]);
});

test("reject flow", async ({ page }) => {
  await login(page, "alice");
  await page.goto(`/approvals/${fx.reject}`);
  await page.getByLabel("Reason (recorded, signed)").fill("recipient not on the list");
  await page.getByRole("button", { name: "Reject" }).click();
  await expect(page.getByRole("status")).toContainText("Rejected");
  await expect(page.getByText("REJECTED").first()).toBeVisible();
});

test("expired approval shows expired and cannot be decided", async ({ page }) => {
  await login(page, "alice");
  await page.goto(`/approvals/${fx.expired}`);
  await expect(page.getByTestId("countdown")).toHaveText("EXPIRED");
  await expect(page.getByTestId("expired-notice")).toContainText("Expired");
  await expect(page.getByRole("button", { name: "Approve exactly this action" })).toHaveCount(0);
});

test("CRITICAL approval requires step-up re-authentication", async ({ page }) => {
  await login(page, "alice");
  await page.goto(`/approvals/${fx.critical}`);
  await expect(page.getByText("CRITICAL").first()).toBeVisible();
  await page.getByRole("button", { name: "Approve exactly this action" }).click();
  await expect(page.locator('[role="status"], [role="alert"]').first()).toContainText("step-up");
  await page.getByLabel(/re-enter your password/).fill(fx.password);
  await page.getByRole("button", { name: "Re-authenticate" }).click();
  await expect(page.getByText("re-authenticated")).toBeVisible();
  await page.getByRole("button", { name: "Approve exactly this action" }).click();
  // four-eyes: one of two approvals recorded
  await expect(page.getByRole("status")).toContainText("another approver");
});
