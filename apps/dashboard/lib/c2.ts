import "server-only";

import { headers } from "next/headers";

import { gateway, me } from "@/lib/gateway";
import { csrfToken } from "@/lib/session";

/** Who is looking, their CSRF token and their step-up state: what every C2 admin page needs. */
export async function viewer() {
  const gw = await gateway();
  const [who, csrf, session] = await Promise.all([me(), csrfToken(), gw.GET("/v1/dashboard/session")]);
  return {
    gw,
    who,
    csrf,
    isAdmin: who.roles.includes("admin"),
    stepUpRemaining: session.data?.step_up_remaining_seconds ?? null,
    stepUpWindow: session.data?.step_up_window_seconds ?? who.step_up_window_seconds ?? 300,
  };
}

/** This dashboard's own origin as the browser used it (for links developers copy). */
export async function dashboardOrigin(): Promise<string> {
  const h = await headers();
  const host = h.get("x-forwarded-host") ?? h.get("host") ?? "localhost:3000";
  const proto = h.get("x-forwarded-proto") ?? (host.startsWith("localhost") || host.startsWith("127.") ? "http" : "https");
  return `${proto}://${host}`;
}

/** Plain-language text for result / error codes carried back in ?result= / ?error=. */
const MESSAGES: Record<string, [string, "good" | "bad" | "warn"]> = {
  CREATED: ["Connector created. Its actions start unclassified (denied) until you classify them.", "good"],
  UPDATED: ["Configuration saved. Test the connection again.", "good"],
  TESTED_OK: ["Connection test passed.", "good"],
  TESTED_FAILED: ["Connection test failed. See the health history for the code.", "bad"],
  CLASSIFIED: ["Classification saved as a new policy version.", "good"],
  UNCHANGED: ["Nothing changed: the classification is the same as the current policy version.", "warn"],
  ROTATED: ["Credentials rotated. The old values are destroyed; test the connection again.", "good"],
  DISABLED: ["Connector disabled. All its actions are denied.", "good"],
  ENABLED: ["Connector enabled. Test the connection to mark it connected.", "good"],
  DELETED: ["Connector deleted and its sealed credentials destroyed.", "good"],
  APPROVED: ["Proposal approved: a new repository policy version applies.", "good"],
  REJECTED: ["Proposal rejected. Nothing was loosened.", "good"],
  STEP_UP_REQUIRED: ["Re-enter your password (step-up) first. Nothing was changed.", "warn"],
  STEP_UP_FAILED: ["Step-up failed: the password was not accepted. Nothing was changed.", "bad"],
  FORBIDDEN: ["Your role cannot do this, or it is no longer possible. Nothing was changed.", "bad"],
  CONFLICT: ["That slug is already used by another connector in this tenant.", "bad"],
  NOT_FOUND: ["Not found in your tenant.", "bad"],
  REQUEST_INVALID: ["The gateway rejected some fields. Check them and try again. Nothing was changed.", "bad"],
  BAD_JSON: ["The actions JSON is not valid. Nothing was changed.", "bad"],
  BAD_FORM: ["The form was incomplete. Nothing was changed.", "bad"],
  KEY_UNAVAILABLE: ["The gateway has no encryption key configured, so credentials cannot be stored.", "bad"],
  DEPENDENCY_UNAVAILABLE: ["The gateway could not reach a dependency. Try again.", "bad"],
};

export function message(code: string | undefined): { text: string; kind: "good" | "bad" | "warn" } | null {
  if (!code) return null;
  const m = MESSAGES[code];
  return m ? { text: m[0], kind: m[1] } : { text: `The gateway answered ${code}. Nothing was changed.`, kind: "bad" };
}

/** Field names from ?fields= (names only: values never travel in a URL). */
export function fieldsOf(raw: string | undefined): string[] {
  return (raw ?? "").split(",").filter((f) => /^[A-Za-z0-9_.<>-]{1,80}$/.test(f)).slice(0, 20);
}
