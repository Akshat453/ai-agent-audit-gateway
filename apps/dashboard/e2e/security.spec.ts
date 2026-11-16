import { expect, test } from "@playwright/test";

import { csrfOf, fx, login } from "./helpers";

test("auditor cannot approve (no form, and the gateway refuses a forged post)", async ({ page }) => {
  await login(page, "audrey");
  await page.goto(`/approvals/${fx.auditor_view}`);
  await expect(page.getByText(/can view but not decide/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve exactly this action" })).toHaveCount(0);
  const csrf = await csrfOf(page); // a valid token for audrey's own session
  const r = await page.request.post(`/api/approvals/${fx.auditor_view}/decision`, {
    form: { csrf, decision: "APPROVE", reason: "", action_digest: "0".repeat(64), nonce: "0".repeat(32) },
    headers: { Origin: new URL(page.url()).origin },
    maxRedirects: 0,
  });
  expect(r.status()).toBe(303);
  expect(r.headers()["location"]).toContain("error=FORBIDDEN");
});

test("approver cannot see payloads: no bundle/payload access without a grant", async ({ page }) => {
  await login(page, "alice");
  await page.goto("/evidence");
  await expect(page.getByText(/Payloads .* are never shown here/)).toBeVisible();
  await expect(page.getByRole("link", { name: "download" })).toHaveCount(0);
  const html = await page.content();
  expect(html).not.toContain("approve me"); // an arg VALUE never appears in the explorer
  const r = await page.request.get(`/api/bundles/${fx.run}`);
  expect([403, 404]).toContain(r.status());
});

test("CSRF: decision without / with a wrong token / cross-site is rejected", async ({ page }) => {
  await login(page, "alice");
  await page.goto(`/approvals/${fx.csrf_target}`);
  const origin = new URL(page.url()).origin;
  const digest = (await page.getByTestId("digest").textContent()) ?? "";
  const base = { decision: "APPROVE", reason: "", action_digest: digest, nonce: "0".repeat(32) };
  const noToken = await page.request.post(`/api/approvals/${fx.csrf_target}/decision`, { form: base, headers: { Origin: origin }, maxRedirects: 0 });
  expect(noToken.status()).toBe(403);
  expect(await noToken.json()).toEqual({ error: "CSRF_TOKEN_INVALID" });
  const wrong = await page.request.post(`/api/approvals/${fx.csrf_target}/decision`, { form: { ...base, csrf: "x".repeat(43) }, headers: { Origin: origin }, maxRedirects: 0 });
  expect(wrong.status()).toBe(403);
  const csrf = await csrfOf(page);
  const crossSite = await page.request.post(`/api/approvals/${fx.csrf_target}/decision`, {
    form: { ...base, csrf },
    headers: { Origin: "https://evil.example", "Sec-Fetch-Site": "cross-site" },
    maxRedirects: 0,
  });
  expect(crossSite.status()).toBe(403);
  expect(await crossSite.json()).toEqual({ error: "CROSS_SITE_REQUEST" });
  await page.reload();
  await expect(page.getByText("PENDING").first()).toBeVisible(); // nothing was decided
});

test("XSS: malicious tool args render as inert, escaped text", async ({ page }) => {
  let dialogs = 0;
  page.on("dialog", (d) => { dialogs++; void d.dismiss(); });
  await login(page, "alice");
  await page.goto(`/approvals/${fx.xss}`);
  const args = page.getByLabel("arguments");
  await expect(args).toContainText("<img src=x onerror=");
  await expect(args).toContainText("<script>window.__xss=2</script>");
  await expect(args.locator("img, script")).toHaveCount(0);
  await expect(page.getByTestId("truncated").first()).toContainText("TRUNCATED");
  expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined();
  expect(dialogs).toBe(0);
});
