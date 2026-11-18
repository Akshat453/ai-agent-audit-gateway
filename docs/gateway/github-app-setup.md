# GitHub App setup for AgentGuard (owner steps)

Status: C3 (ADR-0036), 2026-11-18. Repository: **Akshat453/MintRail**. GitHub facts checked against docs.github.com on 2026-11-18 (REST API version `2026-03-10`).

AgentGuard is the only thing that pushes agent work to GitHub:
- agents never hold a GitHub credential;
- the App's private key and webhook secret live only in the gateway, as write-only connector credentials (Phase 7 envelope-encrypted);
- GitHub refuses merges into `main` unless the **AgentGuard evidence** check is green.

> Never put the private key or webhook secret in a repository, in a `.env` file that could be committed, in a chat, or on a command line. Paste them only into the dashboard's credential fields. They cannot be read back, only rotated.

## 0. Before you start

You need:
- the gateway reachable at a public **https** URL (`AGW_PUBLIC_URL`), or polling mode (§4);
- a dashboard admin account with a recent step-up (the dashboard asks for your password again);
- admin rights on `Akshat453/MintRail`.

## 1. Preferred: create the App from the dashboard (manifest flow)

1. Dashboard → **Integrations** → **GitHub** → **Add**.
   - Owner type: **User**.
   - Owner: `Akshat453`.
   - Repositories: `Akshat453/MintRail`.
   - Mode: **webhook**, or **polling** if the gateway has no public URL.
2. Open the new connector and click **Prepare App registration**, then **Create GitHub App**. Your browser posts a manifest to GitHub with the permissions and events pre-filled:

   | Permission | Access |
   |---|---|
   | Contents | Read and write |
   | Pull requests | Read and write |
   | Issues | Read and write |
   | Checks | Read and write |
   | Metadata | Read |

   Events: `pull_request`, `check_suite`, `issue_comment`, `push`. The webhook URL is `<AGW_PUBLIC_URL>/v1/webhooks/github/<connector id>`.
3. On GitHub, keep the name (or use **AgentGuard-Akshat453**) and click **Create GitHub App**. GitHub redirects back to the gateway.
4. The gateway exchanges the one-time code. This must happen **within one hour**. It stores the App id, slug, client id, **private key**, **webhook secret** and **client secret** as sealed connector credentials. You never see or copy them.
5. Back on the connector page, click **Get install link** → **Install on repositories** → choose **Only select repositories** → **Akshat453/MintRail** → **Install**. GitHub redirects back and the installation id is recorded.
6. Click **Test connection**. The health shows `OK` with 1 installation.
7. **Actions** tab → **Accept proposed classification**.
   - Proposed defaults: issue get/list and PR status are LOW; comments, `git_submit_change` and PR create are MEDIUM.
   - Allowed agents: enrolled developer devices. Approver: maintainer.
   - Review them, then accept. Until you do, every GitHub action is **denied**.

## 2. Fallback: create the App manually

1. GitHub → your avatar → **Settings** → **Developer settings** → **GitHub Apps** → **New GitHub App**.
2. Fill in:
   - **GitHub App name:** `AgentGuard-Akshat453`.
   - **Homepage URL:** your dashboard URL.
   - **Webhook:** Active. URL `<AGW_PUBLIC_URL>/v1/webhooks/github/<connector id>`.
   - **Webhook secret:** a new random value, e.g. from `python3 -c "import secrets;print(secrets.token_urlsafe(32))"`. Keep it only until step 5.
   - **Permissions:** exactly the table in §1.
   - **Events:** `pull_request`, `check_suite`, `issue_comment`, `push`.
   - **Where can this GitHub App be installed?** Only on this account.
3. **Create GitHub App**. Note the **App ID** and **Client ID** (both are public identifiers).
4. **Generate a private key**. A `.pem` file downloads.
5. Dashboard → the GitHub connector:
   - **Edit**: set App ID and Client ID.
   - **Rotate credentials**: paste the private key (`pem`) and the webhook secret.
   - Then **delete the downloaded `.pem`** from your disk.
6. Install the App **only** on `Akshat453/MintRail`: App settings → **Install App** → **Only select repositories**. Record the installation through the connector's **Get install link**, so the gateway learns the installation id with a single-use state. A hand-typed id is not accepted.
7. **Test connection**, then **Accept proposed classification** (§1, steps 6–7).

## 3. Make the check mandatory and block direct pushes

Do this after the **AgentGuard evidence** check has run once (open a test PR first). GitHub only offers checks it has seen in the last seven days.

1. MintRail → **Settings** → **Rules** → **Rulesets** → **New ruleset** → **New branch ruleset**.
2. **Name:** `protect-main`. **Enforcement:** Active. **Target:** Include default branch.
3. Rules:
   - **Require a pull request before merging.**
   - **Require status checks to pass:** add `AgentGuard evidence` and set the expected source to your App, so nobody else can post a green check under that name.
   - **Block force pushes** and **Restrict deletions** (on by default).
4. **Create**.
5. This is a personal repository, so there are no bypass lists or push restrictions for others. Rely on **Require a pull request** and do not grant bypass. Agents cannot push anyway: they hold no credential, and AgentGuard denies `git push` (C1).
6. Optional, if `main` is an org repository later: also **Restrict updates** to the App.

## 4. Webhook delivery for local development

**Option A: tunnel.**
- cloudflared: `cloudflared tunnel --url http://localhost:8000`. This gives a temporary `*.trycloudflare.com` URL that changes each run, so update the App's Webhook URL each time.
- smee: `npx smee -u https://smee.io/<channel> -t http://localhost:8000/v1/webhooks/github/<connector id>`. Channels are public URLs; the gateway verifies `X-Hub-Signature-256` on every delivery, so a forged delivery changes nothing.

**Option B: polling mode** (no public URL). Set the connector's mode to **polling**. The worker lists open PRs every `AGW_GITHUB_POLL_SECONDS` (default 60) and evaluates those whose head changed. Checks still post to GitHub, because the gateway only needs outbound access to `api.github.com` and `github.com`.

## 5. What a developer does

1. `agw login` once, then `agw init` in the MintRail checkout. The agent's MCP config now includes the AgentGuard dev-tools.
2. In the agent: read the issue, change code locally, then call `git_submit_change` (bundle or diff, branch `fix/MR-<issue>-<slug>` or `feat/MR-<issue>-<slug>`) and `github_pr_create`.
3. Sensitive diffs wait for an approval in the dashboard: `ledger/**` → ledger lead; CI, infra or deleting tests → two security approvers.

## 6. Live verification (after steps 1–3)

```sh
AGW_GITHUB_LIVE=1 AGW_LIVE_GATEWAY=https://<gateway> AGW_LIVE_DEVICE_KEY_FILE=~/.config/agentguard/device.key \
AGW_LIVE_SLUG=gh AGW_LIVE_ISSUE=<open issue #> AGW_LIVE_MINTRAIL=~/Desktop/MintRail \
uv run pytest apps/gateway/tests/e2e/test_github_live.py -m e2e
```

The test:
- reads the issue;
- submits a one-line doc change on a new branch;
- opens a PR and expects the check to reach **success**;
- pushes a commit directly with your own git credentials and expects **failure** ("commits not recorded by AgentGuard").

It creates a PR and a branch in MintRail. Close and delete them afterwards.

## 7. Rotating or revoking

- **Private key:** GitHub App settings → **Generate a private key** → dashboard **Rotate credentials** → delete the old key on GitHub.
- **Webhook secret:** change it in the App settings and in **Rotate credentials** at the same time (deliveries fail in between).
- **Disable** the connector in the dashboard to stop every GitHub action at once. **Uninstall** the App on GitHub to revoke all access.
