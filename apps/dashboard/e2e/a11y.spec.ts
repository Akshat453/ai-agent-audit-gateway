import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { fx, login, watch } from "./helpers";

const SCREENS = () => [
  "/", "/runs", `/runs/${fx.child_run}`, "/approvals", `/approvals/${fx.auditor_view}`, "/evidence",
  "/epochs", "/verification", "/policies", "/incidents",
];

test("axe: no serious/critical accessibility violations; no CSP violations", async ({ page }) => {
  const problems = watch(page);
  await page.goto("/login");
  const loginScan = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa"]).analyze();
  expect(loginScan.violations.filter((v) => v.impact === "serious" || v.impact === "critical")).toEqual([]);
  await login(page, "adam");
  for (const path of SCREENS()) {
    await page.goto(path);
    const scan = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa"]).analyze();
    const bad = scan.violations
      .filter((v) => v.impact === "serious" || v.impact === "critical")
      .map((v) => `${path}: ${v.id} (${v.nodes.length})`);
    expect(bad, path).toEqual([]);
  }
  expect(problems).toEqual([]);
});
