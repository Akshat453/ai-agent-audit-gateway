/** A same-origin, path-only redirect target ("/x?y"): never "//host", "/\host", a scheme or
 *  control characters. Anything else falls back. Pure: safe in pages and route handlers. */
export function safeNext(raw: string | null | undefined, fallback = "/"): string {
  if (!raw || raw.length > 2048 || !raw.startsWith("/") || raw.startsWith("//")) return fallback;
  if (/[\u0000-\u001f\u007f\\]/.test(raw)) return fallback;
  return raw;
}
