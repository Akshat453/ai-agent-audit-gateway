/** Side-nav and command-palette destinations (§4), grouped as in the design. `roles` limits who
 *  sees an item (the gateway enforces the same rule on the data). `key` is the "g <key>" jump.
 *  `ready: false` items are Part B pages: hidden until they exist (no dead ends). */
export type NavItem = {
  href: string;
  label: string;
  icon: string;
  key?: string;
  roles?: string[];
  badge?: "approvals";
  ready?: boolean;
  match?: string[];
};
export type NavGroup = { label: string | null; items: NavItem[] };

const ANY = undefined;
// C1 (ADR-0034): the routed approving roles see approvals too.
const VIEWERS = ["approver", "security", "ledger_lead", "maintainer", "auditor", "admin"];
const AUDIT = ["auditor", "admin"];
// C2 (ADR-0035): the gateway enforces the same viewer sets on the data.
const CONNECTOR_VIEWERS = ["admin", "auditor", "security"];
const REPO_VIEWERS = ["admin", "auditor", "security", "maintainer"];
const ADMIN = ["admin"];

export const NAV: NavGroup[] = [
  { label: null, items: [{ href: "/", label: "Overview", icon: "home", key: "o", roles: ANY }] },
  {
    label: "Operations",
    items: [
      { href: "/runs", label: "Runs", icon: "runs", key: "r" },
      { href: "/actions", label: "Actions", icon: "actions", match: ["/actions/"], ready: false },
      { href: "/approvals", label: "Approvals", icon: "approvals", key: "a", roles: VIEWERS, badge: "approvals" },
    ],
  },
  {
    label: "Evidence",
    items: [
      { href: "/evidence", label: "Events", icon: "events", key: "e", match: ["/events/"] },
      { href: "/epochs", label: "Epochs & anchors", icon: "epochs" },
      { href: "/verification", label: "Verification", icon: "verify", key: "v" },
    ],
  },
  {
    label: "Governance",
    items: [
      { href: "/agents", label: "Agents", icon: "agents", ready: false },
      { href: "/tools", label: "Tools", icon: "tools", ready: false },
      { href: "/policies", label: "Policies", icon: "policies", key: "p" },
      { href: "/delegations", label: "Delegations", icon: "delegations", ready: false },
    ],
  },
  {
    label: "Security",
    items: [
      { href: "/incidents", label: "Incidents", icon: "incidents", key: "i" },
      { href: "/alerts", label: "Alerts", icon: "alerts", ready: false },
      { href: "/disclosures", label: "Disclosure grants", icon: "grants", roles: AUDIT, ready: false },
    ],
  },
  {
    label: "Setup",
    items: [
      { href: "/integrations", label: "Integrations", icon: "integrations", roles: CONNECTOR_VIEWERS },
      { href: "/repos", label: "Repositories", icon: "repos", roles: REPO_VIEWERS },
      { href: "/people", label: "People", icon: "people", roles: ADMIN },
      { href: "/enroll", label: "Enroll a device", icon: "enroll", roles: ANY },
    ],
  },
];

export function visibleNav(roles: string[]): NavGroup[] {
  return NAV.map((g) => ({
    ...g,
    items: g.items.filter((i) => i.ready !== false && (!i.roles || i.roles.some((r) => roles.includes(r)))),
  })).filter((g) => g.items.length > 0);
}

export function isActive(item: NavItem, pathname: string): boolean {
  if (item.href === "/") return pathname === "/";
  return pathname === item.href || pathname.startsWith(`${item.href}/`) || (item.match ?? []).some((m) => pathname.startsWith(m));
}
