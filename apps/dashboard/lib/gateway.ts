import "server-only";

import createClient from "openapi-fetch";
import { headers } from "next/headers";
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

/** Redirect to /login and come back to the requested page afterwards. */
export async function toLogin(): Promise<never> {
  const here = (await headers()).get("x-pathname") ?? "/";
  redirect(here.startsWith("/") && !here.startsWith("//") && here !== "/" && !here.startsWith("/login")
    ? `/login?next=${encodeURIComponent(here)}` : "/login");
}

/** For pages: the typed client for the logged-in human, or a redirect to /login. */
export async function gateway() {
  const token = await sessionToken();
  if (!token) return toLogin();
  return gatewayFor(token);
}

export async function me(): Promise<Schemas["DashboardConfig"]> {
  const { data, response } = await (await gateway()).GET("/v1/dashboard/config");
  if (response.status === 401 || !data) return toLogin();
  return data;
}

/** Untyped JSON from endpoints whose schema is free-form (the approval view). */
export async function getJson<T>(path: string): Promise<{ status: number; body: T | null }> {
  const token = await sessionToken();
  if (!token) return toLogin();
  const r = await fetch(GATEWAY_URL + path, {
    headers: { Authorization: `Session ${token}` },
    cache: "no-store",
  });
  if (r.status === 401) return toLogin();
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

/** Any-method JSON call for the C2 admin endpoints (their request bodies are free-form, so the
 *  typed client cannot send them). The body is never logged: it may carry credentials. */
export async function sendJson(method: "POST" | "PATCH" | "DELETE", path: string, token: string, body?: unknown) {
  const r = await fetch(GATEWAY_URL + path, {
    method,
    headers: { Authorization: `Session ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
    body: body === undefined ? undefined : JSON.stringify(body),
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

/** The gateway's uniform error ({error:{code, fields?}}) or an OAuth-style {error: "code"}. */
export function errorOf(status: number, data: unknown): { code: string; fields: string[] } {
  const e = (data as { error?: unknown } | null)?.error;
  if (typeof e === "string") return { code: e, fields: [] };
  const obj = (e ?? {}) as { code?: unknown; fields?: unknown };
  const fields = Array.isArray(obj.fields) ? obj.fields.filter((f): f is string => typeof f === "string").slice(0, 20) : [];
  return { code: typeof obj.code === "string" ? obj.code : `HTTP_${status}`, fields };
}
