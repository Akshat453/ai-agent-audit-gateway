"use client";

import { ExternalLink } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";

type Manifest = { action: string; manifest: unknown };

/** GitHub App registration (manifest flow) and installation (C2). Each step first asks the
 *  dashboard (CSRF + same-origin, admin + step-up on the gateway) for a single-use state, then
 *  hands the browser to github.com: the manifest as a plain form POST (CSP form-action allows
 *  https://github.com on this page only), the installation as a plain link. */
export function GithubPanel({ connectorId, csrf, registered, installations }: {
  connectorId: string; csrf: string; registered: boolean; installations: number;
}) {
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [installUrl, setInstallUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const call = async (what: "github-manifest" | "github-install") => {
    setBusy(true);
    setError(null);
    try {
      const body = new FormData();
      body.set("csrf", csrf);
      const r = await fetch(`/api/connectors/${connectorId}/${what}`, { method: "POST", body, credentials: "same-origin" });
      const d = (await r.json()) as { error?: string; action?: string; manifest?: unknown; url?: string };
      if (!r.ok) {
        setError(d.error === "STEP_UP_REQUIRED" ? "Re-enter your password (step-up) above first." : `The gateway answered ${d.error ?? r.status}.`);
        return;
      }
      if (what === "github-manifest" && d.action) setManifest({ action: d.action, manifest: d.manifest });
      if (what === "github-install" && d.url) setInstallUrl(d.url);
    } catch {
      setError("The request failed. Try again.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4 text-dense" data-testid="github-panel">
      <ol className="space-y-4">
        <li>
          <h3 className="font-medium">1. Register the GitHub App {registered ? <span className="text-caption font-normal text-ok-11">(done)</span> : null}</h3>
          <p className="mb-2 text-caption text-gray-11">GitHub creates an App from a manifest the gateway prepared, then sends you back here. The App&apos;s keys go straight to the gateway, sealed.</p>
          {manifest ? (
            <form method="post" action={manifest.action}>
              <input type="hidden" name="manifest" value={JSON.stringify(manifest.manifest)} />
              <Button type="submit" variant="primary">Create GitHub App<ExternalLink /></Button>
            </form>
          ) : (
            <Button onClick={() => void call("github-manifest")} disabled={busy} variant={registered ? "secondary" : "primary"}>
              {registered ? "Register a new App" : "Prepare App registration"}
            </Button>
          )}
        </li>
        <li>
          <h3 className="font-medium">2. Install on repositories {installations ? <span className="text-caption font-normal text-ok-11">({installations} installation{installations === 1 ? "" : "s"})</span> : null}</h3>
          <p className="mb-2 text-caption text-gray-11">Choose which repositories the App may see. GitHub sends you back here when done.</p>
          {installUrl ? (
            <a href={installUrl} className="inline-flex h-8 items-center gap-1.5 rounded-md bg-brand-9 px-3 text-dense font-medium text-white no-underline hover:bg-brand-10 hover:no-underline">
              Install on repositories<ExternalLink aria-hidden="true" className="size-4" />
            </a>
          ) : (
            <Button onClick={() => void call("github-install")} disabled={busy || !registered}>Get install link</Button>
          )}
          {!registered ? <p className="mt-1 text-caption text-gray-11">Register the App first.</p> : null}
        </li>
      </ol>
      {error ? <p role="alert" className="text-caption font-medium text-bad-11">{error}</p> : null}
    </div>
  );
}
