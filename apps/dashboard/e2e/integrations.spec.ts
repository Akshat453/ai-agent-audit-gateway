import { expect, test, type Page } from "@playwright/test";

import { fx, login, stepUp, watch } from "./helpers";

// C2 (ADR-0035): connectors from the console. Every change needs admin + step-up.
const WEBHOOK = "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXX";
const BOT = "xoxb-test-123";

async function policyVersion(page: Page): Promise<number> {
  const t = (await page.getByTestId("policy-version").first().textContent()) ?? "";
  return Number(/v(\d+)/.exec(t)?.[1] ?? NaN);
}

/** Neither the HTML nor any live form field may hold a credential value. */
async function expectNoSecret(page: Page, secrets: string[]) {
  const html = await page.content();
  const values = await page.evaluate(() => Array.from(document.querySelectorAll("input, textarea")).map((e) => (e as HTMLInputElement).value).join("\n"));
  const text = await page.evaluate(() => document.body.innerText);
  for (const s of secrets) {
    expect(html).not.toContain(s);
    expect(values).not.toContain(s);
    expect(text).not.toContain(s);
  }
}

test("admin adds a Slack connector; its post_message action starts Unclassified (denied)", async ({ page }) => {
  const problems = watch(page);
  await login(page, "adam");
  await page.goto("/integrations");
  await page.getByRole("link", { name: "Add Slack" }).click();
  await expect(page.getByRole("heading", { name: "Add Slack" })).toBeVisible();
  await stepUp(page);
  await page.getByLabel("Display name").fill("E2E Slack");
  await page.getByLabel("Slug").fill("e2eslack");
  await page.getByLabel("Incoming webhook URL").fill(WEBHOOK);
  await page.getByLabel("Bot token (xoxb-…)").fill(BOT);
  await page.getByRole("button", { name: "Create connector" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Connector created" })).toBeVisible();
  await expect(page).toHaveURL(/step=test/);
  await expectNoSecret(page, [WEBHOOK, BOT]);
  await page.getByRole("link", { name: "Continue to classify" }).click();
  const row = page.getByTestId("action-post_message");
  await expect(row).toContainText("post_message");
  await expect(row.getByText(/UNCLASSIFIED/).first()).toBeVisible();
  await expect(page.getByLabel("Risk for post_message")).toHaveValue(""); // stays denied unless chosen
  // the catalog lists it as installed with one unclassified action
  await page.goto("/integrations");
  const installed = page.getByTestId("installed").getByRole("row").filter({ hasText: "E2E Slack" });
  await expect(installed).toContainText("NEEDS ATTENTION");
  await expect(installed.getByTestId("unclassified-count")).toHaveText("1");
  await expectNoSecret(page, [WEBHOOK, BOT]);
  expect(problems).toEqual([]);
});

test("GitHub connector: repositories, delivery mode and protected branches are saved from the form", async ({ page }) => {
  const problems = watch(page);
  await login(page, "adam");
  await page.goto("/integrations/new?type=github");
  await stepUp(page);
  await page.getByLabel("Slug").fill("e2egh");
  await page.getByLabel("Install the App on").selectOption("user");
  await page.getByLabel("Organization or user name").fill("Akshat453");
  await page.getByLabel(/^Repositories/).fill("Akshat453/MintRail");
  await page.getByLabel("How GitHub reaches AgentGuard").selectOption("polling");
  await page.getByRole("button", { name: "Create connector" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Connector created" })).toBeVisible();
  const id = new URL(page.url()).searchParams.get("id") ?? "";
  expect(id).toMatch(/^[0-9a-f-]{36}$/);
  await page.goto(`/integrations/${id}`);
  const status = page.getByTestId("github-status");
  await expect(status).toContainText("Akshat453/MintRail");
  await expect(status).toContainText("polling (every 60 s)");
  expect(problems).toEqual([]);
});

test("classifying post_message creates a new policy version", async ({ page }) => {
  const problems = watch(page);
  await login(page, "adam");
  await page.goto(`/integrations/${fx.connector}`);
  await stepUp(page);
  const before = await policyVersion(page);
  expect(before).toBeGreaterThanOrEqual(0);
  await expect(page.getByTestId("action-post_message").getByText(/UNCLASSIFIED/).first()).toBeVisible();
  await page.getByLabel("Risk for post_message").selectOption("MEDIUM");
  await page.getByLabel("Approval rule for post_message").selectOption("always");
  await page.getByLabel("Approver role for post_message").selectOption("approver");
  await page.getByLabel("Allowed agents for post_message").selectOption("devices");
  await page.getByRole("button", { name: "Save classification" }).click();
  await expect(page.getByRole("status").filter({ hasText: "new policy version" })).toContainText(`policy version v${before + 1}`);
  expect(await policyVersion(page)).toBe(before + 1);
  await expect(page.getByTestId("action-post_message").getByText("CLASSIFIED", { exact: true }).first()).toBeVisible();
  await expect(page.getByLabel("Risk for post_message")).toHaveValue("MEDIUM");
  await page.reload();
  await expect(page.getByTestId("connector-events")).toContainText("CONNECTOR_ACTION_CLASSIFIED");
  // saving the same classification again is not a new version
  await page.getByRole("button", { name: "Save classification" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Nothing changed" })).toBeVisible();
  expect(await policyVersion(page)).toBe(before + 1);
  expect(problems).toEqual([]);
});

test("rotating credentials never puts the secret in the page", async ({ page }) => {
  const problems = watch(page);
  const secret = "https://hooks.slack.com/services/T999/B999/ROTATEDSECRET42";
  await login(page, "adam");
  await page.goto(`/integrations/${fx.connector}`);
  await stepUp(page);
  const version = Number(/version (\d+)/.exec((await page.getByTestId("credentials-view").textContent()) ?? "")?.[1]);
  await page.getByRole("button", { name: "Rotate credentials" }).click();
  const dialog = page.getByTestId("rotate-dialog");
  await dialog.getByLabel("New Incoming webhook URL").fill(secret);
  await dialog.getByLabel("New Bot token (xoxb-…)").fill(BOT);
  await expect(dialog.getByLabel("New Incoming webhook URL")).toHaveAttribute("type", "password");
  await dialog.getByRole("button", { name: "Rotate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "Credentials rotated" })).toContainText(`Credential version ${version + 1}`);
  await expect(page.getByTestId("credentials-view")).toContainText(`version ${version + 1}`);
  await page.reload();
  await expect(page.getByTestId("connector-events")).toContainText("CONNECTOR_CREDENTIAL_ROTATED");
  expect(page.url()).not.toContain("ROTATEDSECRET42");
  await expectNoSecret(page, [secret, "ROTATEDSECRET42", BOT, "SEEDSEEDSEED"]);
  expect(problems).toEqual([]);
});

test("onboarding checklist: progress from real state, admin links work, C3 step open", async ({ page }) => {
  const problems = watch(page);
  await login(page, "adam");
  await page.goto("/");
  const card = page.getByTestId("onboarding");
  await expect(card).toBeVisible();
  await expect(card.getByTestId("onboarding-tenant")).toContainText("(done)");
  await expect(card.getByTestId("onboarding-device")).toContainText("(done)"); // the seed enrolled a device
  const pr = card.getByTestId("onboarding-protected_pr");
  await expect(pr).toContainText("evidence check passed");
  await expect(pr).toContainText("(to do)");
  await card.getByRole("link", { name: /Connect GitHub/ }).click();
  await expect(page).toHaveURL(/\/integrations\/new\?type=github/);
  await expect(page.getByRole("heading", { name: "Add GitHub" })).toBeVisible();
  await page.goto("/");
  await card.getByRole("link", { name: /Add a notification channel/ }).click();
  await expect(page.getByRole("heading", { name: "Add Slack" })).toBeVisible();
  // a non-admin sees progress only
  await login(page, "alice");
  await page.goto("/");
  await expect(page.getByTestId("onboarding")).toBeVisible();
  await expect(page.getByTestId("onboarding").getByRole("link")).toHaveCount(0);
  expect(problems).toEqual([]);
});

test("agent client setup shows the tier, the exact commands and the enrollment link", async ({ page }) => {
  await login(page, "adam");
  await page.goto("/integrations?category=agent_client");
  await page.getByRole("link", { name: "Set up Claude Code" }).click();
  const panel = page.getByTestId("setup-panel");
  await expect(panel).toContainText("ENFORCED");
  await expect(panel.getByLabel("setup commands", { exact: true })).toContainText("agw login --url");
  await expect(panel.getByRole("link", { name: /\/enroll$/ })).toBeVisible();
});

test("device enrollment: the approving human becomes the developer", async ({ page }) => {
  const problems = watch(page);
  await login(page, "alice");
  await page.goto(`/enroll?code=${fx.user_code.toLowerCase()}`);
  const req = page.getByTestId("device-request");
  await expect(req).toContainText("e2e-laptop");
  await expect(req).toContainText("PENDING");
  await req.getByRole("button", { name: "Approve this device" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Approved" }).first()).toBeVisible();
  await expect(page.getByTestId("device-request")).toContainText("APPROVED");
  await expect(page.getByRole("button", { name: "Approve this device" })).toHaveCount(0);
  expect(problems).toEqual([]);
});

test("people: invite shows the temporary password once", async ({ page }) => {
  const problems = watch(page);
  await login(page, "adam");
  await page.goto("/people");
  await stepUp(page);
  await page.getByLabel("Username").fill("newbie");
  await page.getByLabel(/auditor/).check();
  await page.getByRole("button", { name: "Invite" }).click();
  const pw = page.getByTestId("temporary-password");
  await expect(pw).toBeVisible();
  const value = ((await pw.textContent()) ?? "").trim();
  expect(value.length).toBeGreaterThan(10);
  await expect(page.getByTestId("invited")).toContainText("shown only once");
  await page.reload();
  await expect(page.getByTestId("temporary-password")).toHaveCount(0);
  expect(await page.content()).not.toContain(value);
  await expect(page.getByTestId("people")).toContainText("newbie");
  expect(problems).toEqual([]);
});

test("repos: a loosening proposal shows its diff escaped; reject needs a reason and step-up", async ({ page }) => {
  const problems = watch(page);
  await login(page, "adam");
  await page.goto("/repos");
  const prop = page.getByTestId("proposal").first();
  await expect(prop.getByLabel("proposed policy diff")).toContainText("make demo");
  await stepUp(page);
  await prop.getByRole("button", { name: "Reject" }).click();
  await page.getByLabel("Reason (recorded)").fill("not needed for the demo");
  await page.getByRole("button", { name: "Reject proposal" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Proposal rejected" })).toBeVisible();
  await expect(page.getByTestId("proposal")).toHaveCount(0);
  expect(problems).toEqual([]);
});

test("viewer roles: an approver cannot see integrations; the gateway refuses a forged change", async ({ page }) => {
  await login(page, "alice");
  await page.goto("/integrations");
  await expect(page.getByRole("alert").filter({ hasText: "cannot view integrations" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Integrations" })).toHaveCount(0);
  await page.goto("/enroll");
  const csrf = (await page.locator('input[name="csrf"]').first().getAttribute("value")) ?? "";
  const r = await page.request.post(`/api/connectors/${fx.connector}/disable`, {
    form: { csrf }, headers: { Origin: new URL(page.url()).origin }, maxRedirects: 0,
  });
  expect(r.status()).toBe(303);
  expect(r.headers()["location"]).toContain("error=FORBIDDEN");
});
