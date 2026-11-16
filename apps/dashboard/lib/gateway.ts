import "server-only";

import createClient from "openapi-fetch";
import { redirect } from "next/navigation";

import type { components, paths } from "@/lib/api/schema";
import { sessionToken } from "@/lib/session";

/** Server-side only: the browser never talks to the gateway (ADR-0031 §1). */
export const GATEWAY_URL = process.env.AGW_GATEWAY_URL ?? "http://127.0.0.1:8080";

export type Schemas = components["schemas"];

export function gatewayFor(token: string | null) {
  return createClient<paths>({
    baseUrl: GATEWAY_URL,
    headers: token ? { Authorization: `Session ${token}` } : {},
    cache: "no-store",
  });
}

/** For pages: the typed client for the logged-in human, or a redirect to /login. */
export async function gateway() {
  const token = await sessionToken();
  if (!token) redirect("/login");
  return gatewayFor(token);
}

export async function me(): Promise<Schemas["DashboardConfig"]> {
  const { data, response } = await (await gateway()).GET("/v1/dashboard/config");
  if (response.status === 401 || !data) redirect("/login");
  return data;
}

/** Untyped JSON from endpoints whose schema is free-form (the approval view). */
export async function getJson<T>(path: string): Promise<{ status: number; body: T | null }> {
  const token = await sessionToken();
  if (!token) redirect("/login");
  const r = await fetch(GATEWAY_URL + path, {
    headers: { Authorization: `Session ${token}` },
    cache: "no-store",
  });
  if (r.status === 401) redirect("/login");
  return { status: r.status, body: r.ok ? ((await r.json()) as T) : null };
}

export async function postJson(path: string, token: string, body: unknown) {
  const r = await fetch(GATEWAY_URL + path, {
    method: "POST",
    headers: { Authorization: `Session ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
  });
  let data: unknown = null;
  try {
    data = await r.json();
  } catch {
    data = null;
  }
  return { status: r.status, data };
}
