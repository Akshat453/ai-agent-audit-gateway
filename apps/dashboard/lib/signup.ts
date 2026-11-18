import "server-only";

import { GATEWAY_URL } from "@/lib/gateway";

/** Whether the gateway allows self-service sign-up (dev/test only). Fails closed. */
export async function signupEnabled(): Promise<boolean> {
  try {
    const r = await fetch(GATEWAY_URL + "/v1/auth/signup", { cache: "no-store" });
    if (!r.ok) return false;
    return ((await r.json()) as { enabled?: boolean }).enabled === true;
  } catch {
    return false;
  }
}
