import { expect, test } from "@playwright/test";

import { confirmApprove, fx, login, userMenu, watch } from "./helpers";

// Phase 9.5 console behaviour: URL-held table state, split panel, command palette, keyboard-only
// approval, theme + density preferences, and the CSP contract.

test("filter + URL round-trip: token filter, reload, back button", async ({ page }) => {
  const problems = watch(page);
  await login(page, "alice");
  await page.goto("/approvals?state=ALL");
  const filter = page.getByLabel(/Filter Approvals/);
  await filter.fill("risk = CRITICAL");
  await filter.press("Enter");
  await expect(page).toHaveURL(/risk=CRITICAL/);
  await expect(page.getByRole("button", { name: "Remove filter risk = CRITICAL" })).toBeVisible();
  const rows = page.locator("tbody tr[data-row]");
  await expect(rows.first()).toBeVisible();
  for (const text of await rows.allInnerTexts()) expect(text).toContain("CRITICAL");
  await page.reload();
  await expect(page.getByRole("button", { name: "Remove filter risk = CRITICAL" })).toBeVisible(); // survives refresh
  await page.goBack();
  await expect(page).not.toHaveURL(/risk=CRITICAL/);
  await filter.fill("colour = red"); // unknown field: explained, not silently ignored
  await filter.press("Enter");
  await expect(page.getByText(/Use field = value/)).toBeVisible();
  expect(problems).toEqual([]);
});

test("sorting is server-side and in the URL; pagination controls reflect the total", async ({ page }) => {
  await login(page, "alice");
  await page.goto("/approvals?state=ALL");
  await page.getByRole("button", { name: "Sort by Risk" }).click();
  await expect(page).toHaveURL(/sort=risk&order=asc/);
  await page.getByRole("button", { name: "Sort by Risk" }).click();
  await expect(page).toHaveURL(/order=desc/);
  await expect(page.locator("tbody tr[data-row]").first()).toContainText("CRITICAL"); // highest first
  await expect(page.getByRole("navigation", { name: "Pagination" })).toContainText(/of \d+/);
  await expect(page.getByRole("button", { name: "Previous page" })).toBeDisabled();
});

test("split panel: selecting a row opens details in the URL; Esc closes it", async ({ page }) => {
  await login(page, "alice");
  await page.goto("/approvals");
  const row = page.locator(`tbody tr[data-row="${fx.keyboard}"]`);
  await row.click();
  await expect(page).toHaveURL(new RegExp(`sel=${fx.keyboard}`));
  const panel = page.getByRole("complementary", { name: "Details" });
  await expect(panel).toBeVisible();
  await expect(panel.getByRole("link", { name: "Review and decide" })).toHaveAttribute("href", `/approvals/${fx.keyboard}`);
  await expect(panel.getByRole("button", { name: /Approve/ })).toHaveCount(0); // never approve from a list
  await page.keyboard.press("Escape");
  await expect(page).not.toHaveURL(/sel=/);
});

test("command palette: navigate to a page and jump to an entity by id", async ({ page }) => {
  await login(page, "audrey");
  await page.keyboard.press("Control+k");
  const palette = page.getByRole("dialog");
  await palette.getByRole("combobox").fill("Verification");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/verification/);
  await page.keyboard.press("Control+k");
  await page.getByRole("dialog").getByRole("combobox").fill(fx.keyboard_action);
  await expect(page.getByRole("option", { name: /Action · send_email/ })).toBeVisible();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(new RegExp(`/actions/${fx.keyboard_action}`));
  await expect(page.getByRole("list", { name: "Evidence timeline" })).toBeVisible();
  await page.keyboard.press("g");
  await page.keyboard.press("o"); // "g o": go to Overview
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
});

test("keyboard-only approval flow (no mouse)", async ({ page }) => {
  const problems = watch(page);
  await login(page, "carol");
  await page.goto(`/approvals?sel=${fx.keyboard}`);
  const row = page.locator(`tbody tr[data-row="${fx.keyboard}"]`);
  await row.focus();
  await page.keyboard.press("Shift+Enter"); // open the full page from the focused row
  await expect(page).toHaveURL(new RegExp(`/approvals/${fx.keyboard}$`));
  const approve = page.getByRole("button", { name: "Approve exactly this action" });
  await approve.focus();
  await page.keyboard.press("Enter");
  const dialog = page.getByTestId("approve-dialog");
  await expect(dialog).toBeVisible();
  // focus is trapped in the dialog; Tab reaches the confirm button
  for (let i = 0; i < 6 && !(await dialog.getByRole("button", { name: "Confirm approval" }).evaluate((b) => b === document.activeElement)); i++) {
    await page.keyboard.press("Tab");
  }
  await expect(dialog.getByRole("button", { name: "Confirm approval" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("status").filter({ hasText: "Approved" }).first()).toBeVisible();
  expect(problems).toEqual([]);
});

test("dark mode and density persist server-side (cookie), no flash, no inline script", async ({ page }) => {
  const problems = watch(page);
  await login(page, "audrey");
  await expect(page.locator("html")).toHaveClass(/\blight\b/);
  await page.getByTestId("theme-toggle").click();
  await expect(page.locator("html")).toHaveClass(/\bdark\b/);
  await page.reload();
  await expect(page.locator("html")).toHaveClass(/\bdark\b/); // rendered by the server from the cookie
  await userMenu(page, "Compact");
  await expect(page.locator("html")).toHaveClass(/density-compact/);
  await page.reload();
  await expect(page.locator("html")).toHaveClass(/density-compact/);
  const rowH = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--row-h").trim());
  expect(rowH).toBe("36px");
  expect(await page.evaluate(() => document.cookie)).toBe(""); // preference cookies are httpOnly too
  await page.getByTestId("theme-toggle").click();
  await userMenu(page, "Comfortable");
  expect(problems).toEqual([]);
});

test("CSP: per-request nonce, no unsafe-inline / unsafe-eval, no external origins", async ({ page }) => {
  await login(page, "alice");
  const a = await page.goto("/");
  const b = await page.goto("/approvals");
  const csp = a?.headers()["content-security-policy"] ?? "";
  const csp2 = b?.headers()["content-security-policy"] ?? "";
  const nonce = csp.match(/'nonce-([^']+)'/)?.[1];
  expect(nonce).toBeTruthy();
  expect(csp2).not.toContain(`'nonce-${nonce}'`); // fresh per request
  expect(csp).toMatch(/script-src 'self' 'nonce-[^']+' 'strict-dynamic'/);
  expect(csp).toMatch(/style-src 'self' 'nonce-[^']+'/);
  expect(csp).not.toMatch(/unsafe-inline|unsafe-eval|unsafe-hashes/);
  expect(csp).not.toMatch(/https?:\/\//); // no external origins anywhere
  for (const src of await page.locator("script[src], link[href]").evaluateAll((els) => els.map((e) => e.getAttribute("src") ?? e.getAttribute("href") ?? ""))) {
    expect(src.startsWith("/") || src.startsWith("data:"), src).toBe(true); // self-hosted only
  }
  for (const path of ["/", "/approvals", `/approvals/${fx.critical}`, `/actions/${fx.keyboard_action}`]) {
    const html = await (await page.request.get(path)).text();
    expect(html, path).not.toMatch(/<[a-z]+[^>]*\sstyle="/); // no server-rendered style attributes
  }
});

test("plain-English explanations: action timeline steps and the event page", async ({ page }) => {
  const problems = watch(page);
  await login(page, "alice");
  await page.goto(`/actions/${fx.keyboard_action}`);
  const first = page.locator('[data-testid^="node-plain-"]').first();
  await expect(first).toContainText(/asked to/);
  const ev = await page.locator('ol[aria-label="Evidence timeline"] a[href^="/events/"]').first().getAttribute("href");
  await page.goto(ev ?? "/");
  await expect(page.getByTestId("event-plain")).toContainText(/The AI agent asked to/);
  await expect(page.getByRole("heading", { name: "Raw record" })).toBeVisible();
  expect(problems).toEqual([]);
});
