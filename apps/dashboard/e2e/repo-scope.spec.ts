import { expect, test } from "@playwright/test";

import { fx, login, watch } from "./helpers";

// ADR-0040: with more than one repository, the console can show one repository at a time.

test("repository switcher scopes runs, approvals, events and incidents; remembered; one click back", async ({ page }) => {
  const problems = watch(page);
  await login(page, "adam", "simple");
  await page.goto("/runs");
  await expect(page.getByTestId("run-sentences")).toContainText("seed-repo");
  await expect(page.getByTestId("run-sentences")).toContainText("second-repo");

  await page.getByTestId("repo-switcher").click();
  await page.getByRole("menuitemradio", { name: /^second-repo/ }).click();
  await expect(page.getByTestId("repo-banner")).toContainText("Showing only second-repo");
  await expect(page.getByTestId("run-sentences")).toContainText("second-repo - issue #3");
  await expect(page.getByTestId("run-sentences")).not.toContainText("seed-repo");
  await expect(page.locator(`a[href="/runs/${fx.coding_run}"]`)).toHaveCount(0);

  // remembered across pages and reloads
  await page.goto("/approvals");
  await expect(page.getByTestId("repo-banner")).toBeVisible();
  await expect(page.getByTestId("approval-sentence")).toHaveCount(0); // second-repo has no approvals
  await page.goto("/evidence");
  await expect(page.getByTestId("event-sentences")).not.toContainText("signal/src/sign.ts");

  await page.getByTestId("repo-switcher").click();
  await page.getByRole("menuitemradio", { name: /^seed-repo/ }).click();
  await page.goto("/approvals");
  await expect(page.getByTestId("approval-sentence")).toHaveCount(1);
  await expect(page.getByTestId("approval-sentence")).toContainText(".claude/settings.json");
  await page.goto("/incidents");
  await expect(page.getByTestId("incident-sentences")).not.toContainText("send an email");

  await page.getByRole("button", { name: "Show all repositories" }).click();
  await expect(page.getByTestId("repo-banner")).toHaveCount(0);
  await page.goto("/runs");
  await expect(page.getByTestId("run-sentences")).toContainText("second-repo");
  expect(problems).toEqual([]);
});

test("run story: structured rows, one outcome each, why, and filters", async ({ page }) => {
  await login(page, "adam", "technical");
  await page.goto(`/runs/${fx.coding_run}`);
  const story = page.getByTestId("run-story"); // shown in Technical view too
  await expect(story.getByTestId("story-counts")).toContainText("steps:");
  const row = (text: string) => story.getByRole("listitem").filter({ hasText: text });
  await expect(row("README.md")).toContainText("Read file");
  await expect(row("README.md")).toContainText("Allowed");
  await expect(row("pnpm test").first()).toContainText("Command");
  await expect(row("pnpm test").first().getByTestId("story-summary")).toHaveText("Run the tests"); // meaning, not the raw command
  await expect(row("signal/src/sign.ts")).toContainText("Why: The change would remove webhook signature checks.");
  await expect(row("uploads.example.com")).toContainText("Why: The command talks to another computer");
  await expect(row(".claude/settings.json")).toContainText("Waiting for approval");
  // an allow-only rule never shows up as the reason for a block or an approval
  await expect(story.getByText("Why: A routine command")).toHaveCount(0);
  await story.getByRole("link", { name: "Blocked" }).click();
  await expect(page).toHaveURL(/show=blocked/);
  await expect(page.getByTestId("story-rows").getByRole("listitem")).toHaveCount(2);
  await page.getByTestId("run-story").getByRole("link", { name: "Commands" }).click();
  await expect(page.getByTestId("story-rows")).not.toContainText("README.md");
});
