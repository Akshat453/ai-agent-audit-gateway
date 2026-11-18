import {
  Activity, Anchor, BadgeCheck, Bell, Boxes, FileKey2, GitFork, LayoutDashboard, ListTree, Scale,
  ScrollText, ShieldAlert, ShieldCheck, Workflow, Wrench, Plug, FolderGit2, Users, Laptop, type LucideIcon,
} from "lucide-react";

export const NAV_ICONS: Record<string, LucideIcon> = {
  home: LayoutDashboard,
  runs: Workflow,
  actions: Activity,
  approvals: ShieldCheck,
  events: ListTree,
  epochs: Anchor,
  verify: BadgeCheck,
  agents: Boxes,
  tools: Wrench,
  policies: Scale,
  delegations: GitFork,
  incidents: ShieldAlert,
  alerts: Bell,
  grants: FileKey2,
  logs: ScrollText,
  integrations: Plug,
  repos: FolderGit2,
  people: Users,
  enroll: Laptop,
};
