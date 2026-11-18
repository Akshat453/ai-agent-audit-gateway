import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { fx, login, watch } from "./helpers";

const SCREENS = () => [
  "/", "/runs", `/runs/${fx.child_run}`, "/approvals", `/approvals?sel=${fx.auditor_view}`, `/approvals/${fx.auditor_view}`,
  `/actions/${fx.keyboard_action}`, "/evidence", "/epochs", "/verification", "/policies", "/incidents",
  // C2 (ADR-0035)
  "/integrations", `/integrations/${fx.connector}`, "/integrations/new?type=slack", "/integrations/new?type=http_api",
  "/integrations/new?type=claude_code", "/repos", "/people", "/enroll", `/enroll?code=${fx.user_code}`, "/oauth/consent?client_id=x",
];

// Phase 9.5: every page in BOTH themes; zero serious/critical axe findings, zero CSP violations.
for (const theme of ["light", "dark"] as const) {
  test(`axe (${theme}): no serious/critical accessibility violations; no CSP violations`, async ({ page, context, baseURL }) => {
    test.setTimeout(300_000); // 24 pages scanned per theme; the default 30 s is per test
    const problems = watch(page);
    await context.addCookies([{ name: "agw_theme", value: theme, url: baseURL ?? "http://localhost:23000", httpOnly: true, secure: true, sameSite: "Strict" }]);
    await page.goto("/login");
    const loginScan = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa"]).analyze();
    expect(loginScan.violations.filter((v) => v.impact === "serious" || v.impact === "critical")).toEqual([]);
    await page.goto("/signup");
    const signupScan = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa"]).analyze();
    expect(signupScan.violations.filter((v) => v.impact === "serious" || v.impact === "critical")).toEqual([]);
    await login(page, "adam");
    await expect(page.locator("html")).toHaveClass(new RegExp(`\\b${theme}\\b`));
    const screens = SCREENS();
    // an event page (the proof explorer) reached from the action's evidence timeline
    await page.goto(`/actions/${fx.keyboard_action}`);
    const ev = await page.locator('ol[aria-label="Evidence timeline"] a[href^="/events/"]').first().getAttribute("href");
    if (ev) screens.push(ev);
    for (const path of screens) {
      await page.goto(path);
      await page.waitForLoadState("networkidle");
      const scan = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa"]).analyze();
      const bad = scan.violations
        .filter((v) => v.impact === "serious" || v.impact === "critical")
        .map((v) => `${path}: ${v.id} (${v.nodes.length}) ${v.nodes.slice(0, 2).map((n) => n.target.join(" ")).join(" | ")}`);
      expect(bad, path).toEqual([]);
    }
    expect(problems).toEqual([]);
  });
}
