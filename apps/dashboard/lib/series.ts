/** Decision series for the activity chart. ok (jade) / warn (amber) / bad (tomato) follow the
 *  status mapping, so the colors mean the same as the badges. Shared by the server page (legend,
 *  table) and the client chart, so it lives outside the "use client" module. */
export const SERIES = [
  { key: "ALLOW", label: "Allowed", color: "var(--jade-9)" },
  { key: "REQUIRE_APPROVAL", label: "Needed approval", color: "var(--amber-9)" },
  { key: "DENY", label: "Denied", color: "var(--tomato-9)" },
] as const;
