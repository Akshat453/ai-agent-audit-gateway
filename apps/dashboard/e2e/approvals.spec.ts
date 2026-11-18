import { expect, test } from "@playwright/test";

import { confirmApprove, fx, login, watch } from "./helpers";

test("approve flow: exact action shown, approve echoes digest + nonce, action authorized", async ({ page }) => {
  const problems = watch(page);
  await login(page, "alice");
  await page.goto("/approvals");
  await page.getByRole("link", { name: new RegExp(fx.approve) }).click(); // id chip: full id in its accessible name
  await expect(page.getByRole("heading", { name: /send_email@1.0.0/ })).toBeVisible();
  await expect(page.getByLabel("arguments")).toContainText("approve me");
  await expect(page.getByTestId("countdown")).toContainText("expires in");
  await confirmApprove(page); // Phase 9.5: confirmation dialog restating the action
  await expect(page.getByRole("status").filter({ hasText: "Approved" }).first()).toContainText("Approved");
  await expect(page.getByText("CONSUMED").first()).toBeVisible(); // single-use: consumed by the authorization
  await expect(page.getByRole("button", { name: "Approve exactly this action" })).toHaveCount(0);
  expect(problems).toEqual([]);
});

test("reject flow", async ({ page }) => {
  await login(page, "alice");
  await page.goto(`/approvals/${fx.reject}`);
  await page.getByRole("button", { name: "Reject" }).click(); // opens the dialog
  const dialog = page.getByTestId("reject-dialog");
  await expect(dialog.getByRole("button", { name: "Reject this action" })).toBeDisabled(); // reason required
  await dialog.getByLabel("Reason (recorded, signed)").fill("recipient not on the list");
  await dialog.getByRole("button", { name: "Reject this action" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Rejected" }).first()).toContainText("Rejected");
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
  const dialog = page.getByTestId("approve-dialog");
  // CRITICAL: confirming needs the last 6 characters of the action id typed exactly
  await expect(dialog.getByRole("button", { name: "Confirm approval" })).toBeDisabled();
  await dialog.getByLabel(/to confirm/).fill("000000");
  await expect(dialog.getByRole("button", { name: "Confirm approval" })).toBeDisabled();
  await dialog.getByLabel(/to confirm/).fill(((await dialog.getByTestId("confirm-code").textContent()) ?? "").trim());
  await dialog.getByRole("button", { name: "Confirm approval" }).click();
  await expect(page.locator('[role="status"], [role="alert"]').filter({ hasText: "step-up" }).first()).toContainText("step-up");
  await page.getByLabel(/re-enter your password/).fill(fx.password);
  await page.getByRole("button", { name: "Re-authenticate" }).click();
  await expect(page.getByText("re-authenticated", { exact: true })).toBeVisible();
  await confirmApprove(page);
  // four-eyes: one of two approvals recorded
  await expect(page.getByRole("status").filter({ hasText: "another approver" }).first()).toContainText("another approver");
});
