"use client";

import {
  Bell, ChevronsLeft, ChevronsRight, Keyboard, LogOut, Moon, Rows3, Search, ShieldCheck, Sun, UserRound,
} from "lucide-react";
import dynamic from "next/dynamic";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useRef, useState, type ReactNode } from "react";

import { ShellProvider, useShell, type ShellPrefs } from "@/components/shell/context";
import { RepoSwitcher, type RepoChoice } from "@/components/humanize/repo-switcher";
import { HelpDrawer } from "@/components/shell/help";
import { LogoMark } from "@/components/shell/logo";
import { NAV_ICONS } from "@/components/shell/nav-icons";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { Kbd } from "@/components/ui/input";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuRadioGroup,
  DropdownMenuRadioItem, DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/menu";
import { Tooltip, TooltipProvider } from "@/components/ui/overlay";
import { Toaster } from "@/components/ui/toast";
import { PRODUCT_NAME, PRODUCT_VERSION } from "@/lib/brand";
import { cn } from "@/lib/cn";
import { isActive, type NavGroup } from "@/lib/nav";

// The palette (cmdk) is code-split: fetched the first time it is opened, not on every page
// load (bundle budget, ADR-0033 §4).
const CommandPalette = dynamic(() => import("@/components/shell/command-palette").then((m) => m.CommandPalette), { ssr: false });

export type ShellUser = {
  username: string;
  roles: string[];
  tenant: string;
  env: string;
  stepUpRemaining: number | null;
  stepUpWindow: number;
};
export type ShellHealth = { worst: "ok" | "degraded" | "down" | "off"; summary: string };

type Props = {
  user: ShellUser;
  nav: NavGroup[];
  pendingApprovals: number;
  alerts24h: number;
  health: ShellHealth;
  csrf: string;
  prefs: ShellPrefs;
  repos?: RepoChoice[];
  children: ReactNode;
};

export function AppShell(props: Props) {
  return (
    <ShellProvider csrf={props.csrf} initialPrefs={props.prefs}>
      <TooltipProvider delayDuration={250}>
        <Frame {...props} />
        <Toaster />
      </TooltipProvider>
    </ShellProvider>
  );
}

function Frame({ user, nav, pendingApprovals, alerts24h, health, repos = [], children }: Props) {
  const shell = useShell();
  const router = useRouter();
  const pathname = usePathname();
  const gPressed = useRef<number>(0);
  const collapsed = shell.prefs.nav === "collapsed";
  const [paletteUsed, setPaletteUsed] = useState(false);
  useEffect(() => { if (shell.paletteOpen) setPaletteUsed(true); }, [shell.paletteOpen]);

  // Global keys (§4): Ctrl/Cmd K palette, "g" then a letter navigates, "?" shortcut sheet.
  useEffect(() => {
    const keys = new Map(nav.flatMap((g) => g.items).filter((i) => i.key).map((i) => [i.key as string, i.href]));
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        shell.setPaletteOpen(!shell.paletteOpen);
        return;
      }
      const el = e.target as HTMLElement;
      if (el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable)) return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === "?") {
        e.preventDefault();
        shell.setShortcutsOpen(true);
      } else if (e.key === "g") {
        gPressed.current = Date.now();
      } else if (Date.now() - gPressed.current < 1200 && keys.has(e.key)) {
        e.preventDefault();
        gPressed.current = 0;
        router.push(keys.get(e.key) as string);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [nav, router, shell]);

  const stepUpMin = user.stepUpRemaining !== null ? Math.max(1, Math.round(user.stepUpRemaining / 60)) : null;
  const healthDot = { ok: "bg-ok-9", degraded: "bg-warn-9", down: "bg-bad-9", off: "bg-gray-8" }[health.worst];

  return (
    <div className="flex min-h-screen flex-col">
      <a href="#main" className="sr-only z-[70] rounded-md bg-brand-9 px-3 py-2 text-white focus:not-sr-only focus:fixed focus:left-3 focus:top-3">Skip to content</a>
      {/* ---------------------------------------------------------------- top bar (48 px) */}
      <header className="sticky top-0 z-40 flex h-12 shrink-0 items-center gap-3 border-b border-gray-6 bg-gray-1/95 px-3 backdrop-blur">
        <a href="/" className="flex items-center gap-2 rounded-md px-1 py-1 text-gray-12 no-underline hover:no-underline" aria-label={`${PRODUCT_NAME} home`}>
          <LogoMark className="size-6" />
          <span className="hidden text-body font-semibold tracking-tight sm:inline">{PRODUCT_NAME}</span>
        </a>
        <span className="hidden items-center gap-1.5 rounded-full border border-gray-6 bg-gray-2 px-2 py-0.5 text-caption text-gray-11 md:inline-flex" title="Tenant">
          <span className="size-1.5 rounded-full bg-brand-9" aria-hidden="true" />tenant <span className="font-medium text-gray-12">{user.tenant}</span>
        </span>
        <RepoSwitcher choices={repos} />
        {user.env !== "prod" ? (
          <span className="rounded-sm border border-warn-7 bg-warn-3 px-1.5 py-px text-[11px] font-semibold uppercase tracking-wide text-warn-12" data-testid="env-badge">
            {user.env}
          </span>
        ) : null}
        <button type="button" onClick={() => shell.setPaletteOpen(true)}
          className="mx-auto flex h-8 w-full max-w-md cursor-pointer items-center gap-2 rounded-md border border-gray-6 bg-gray-2 px-2.5 text-dense text-gray-11 transition-colors hover:border-gray-8 hover:bg-gray-3">
          <Search aria-hidden="true" className="size-4" />
          <span className="flex-1 truncate text-left">Search or jump to…</span>
          <span className="hidden gap-0.5 sm:flex"><Kbd>Ctrl</Kbd><Kbd>K</Kbd></span>
        </button>
        <div className="flex items-center gap-1">
          <Tooltip content={alerts24h ? `${alerts24h} alert(s) in the last 24 h` : "No alerts in the last 24 h"}>
            <a href="/incidents" aria-label={`Alerts: ${alerts24h} in the last 24 hours`} className="relative rounded-md p-2 text-gray-11 hover:bg-gray-4 hover:text-gray-12">
              <Bell className="size-4" />
              {alerts24h ? <span className="absolute right-0.5 top-0.5 min-w-4 rounded-full bg-bad-11 px-1 text-center text-[11px] font-semibold leading-4 text-white tabular dark:bg-bad-10 dark:text-gray-1">{alerts24h > 99 ? "99+" : alerts24h}</span> : null}
            </a>
          </Tooltip>
          <Tooltip content={`Switch to ${shell.prefs.theme === "dark" ? "light" : "dark"} theme`}>
            <button type="button" aria-label={`Switch to ${shell.prefs.theme === "dark" ? "light" : "dark"} theme`}
              onClick={() => void shell.setPref("theme", shell.prefs.theme === "dark" ? "light" : "dark")}
              className="rounded-md p-2 text-gray-11 hover:bg-gray-4 hover:text-gray-12" data-testid="theme-toggle">
              {shell.prefs.theme === "dark" ? <Sun className="size-4" /> : <Moon className="size-4" />}
            </button>
          </Tooltip>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button type="button" className="flex items-center gap-2 rounded-md py-1 pl-1 pr-2 text-dense hover:bg-gray-4" aria-label={`User menu for ${user.username}`}>
                <span className="flex size-6 items-center justify-center rounded-full bg-brand-4 text-caption font-semibold uppercase text-brand-11" aria-hidden="true">{user.username.slice(0, 1)}</span>
                <span className="hidden text-gray-12 md:inline" data-testid="whoami">{user.username} <span className="text-gray-11">({user.roles.join(", ")})</span></span>
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-64">
              <DropdownMenuLabel>
                <div className="flex items-center gap-2 text-gray-12"><UserRound className="size-4 text-gray-11" />{user.username}</div>
                <div className="mt-0.5 font-normal">{user.roles.join(", ")} · tenant {user.tenant}</div>
                <div className={cn("mt-1.5 inline-flex items-center gap-1 font-normal", stepUpMin ? "text-ok-11" : "text-gray-11")} data-testid="step-up-status">
                  <ShieldCheck className="size-3.5" />
                  {stepUpMin ? `Step-up active · ${stepUpMin} min left` : "Step-up not active"}
                </div>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuLabel>View</DropdownMenuLabel>
              <DropdownMenuRadioGroup value={shell.prefs.view} onValueChange={(v) => void shell.setPref("view", v as ShellPrefs["view"])}>
                <DropdownMenuRadioItem value="simple">Simple view (plain English)</DropdownMenuRadioItem>
                <DropdownMenuRadioItem value="technical">Technical view</DropdownMenuRadioItem>
              </DropdownMenuRadioGroup>
              <DropdownMenuLabel>Density</DropdownMenuLabel>
              <DropdownMenuRadioGroup value={shell.prefs.density} onValueChange={(v) => void shell.setPref("density", v as ShellPrefs["density"])}>
                <DropdownMenuRadioItem value="comfortable">Comfortable</DropdownMenuRadioItem>
                <DropdownMenuRadioItem value="compact">Compact</DropdownMenuRadioItem>
              </DropdownMenuRadioGroup>
              <DropdownMenuLabel>Times shown in</DropdownMenuLabel>
              <DropdownMenuRadioGroup value={shell.prefs.tz} onValueChange={(v) => void shell.setPref("tz", v as ShellPrefs["tz"])}>
                <DropdownMenuRadioItem value="local">Local time</DropdownMenuRadioItem>
                <DropdownMenuRadioItem value="utc">UTC</DropdownMenuRadioItem>
              </DropdownMenuRadioGroup>
              <DropdownMenuSeparator />
              <DropdownMenuItem onSelect={() => shell.setShortcutsOpen(true)}><Keyboard />Keyboard shortcuts<Kbd className="ml-auto">?</Kbd></DropdownMenuItem>
              <DropdownMenuItem onSelect={() => (document.getElementById("logout-form") as HTMLFormElement | null)?.requestSubmit()}>
                <LogOut />Log out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </header>

      <div className="flex flex-1">
        {/* -------------------------------------------------------------- side nav */}
        <nav aria-label="Main" className={cn("sticky top-12 hidden h-[calc(100vh-3rem)] shrink-0 flex-col border-r border-gray-6 bg-gray-2 transition-[width] duration-150 ease-out md:flex", collapsed ? "w-14" : "w-60")}>
          <div className="flex-1 overflow-y-auto px-2 py-3">
            {nav.map((g) => (
              <div key={g.label ?? "main"} className="mb-4">
                {g.label && !collapsed ? <div className="mb-1 px-2 text-[11px] font-semibold uppercase tracking-wider text-gray-11">{g.label}</div> : null}
                {g.label && collapsed ? <div className="mx-2 mb-2 h-px bg-gray-5" aria-hidden="true" /> : null}
                <ul className="space-y-0.5">
                  {g.items.map((i) => {
                    const Icon = NAV_ICONS[i.icon];
                    const active = isActive(i, pathname);
                    const badge = i.badge === "approvals" && pendingApprovals > 0 ? pendingApprovals : null;
                    const link = (
                      <a href={i.href} aria-current={active ? "page" : undefined}
                        className={cn("relative flex h-8 items-center gap-2.5 rounded-md px-2 text-dense font-medium no-underline transition-colors hover:no-underline",
                          active ? "bg-brand-4 text-brand-12" : "text-gray-11 hover:bg-gray-4 hover:text-gray-12",
                          collapsed && "justify-center px-0")}>
                        {active ? <span aria-hidden="true" className="absolute -left-2 top-1.5 h-5 w-0.5 rounded-full bg-brand-9" /> : null}
                        {Icon ? <Icon aria-hidden="true" className={cn("size-4 shrink-0", active ? "text-brand-11" : "")} /> : null}
                        <span className={cn("flex-1 truncate", collapsed && "sr-only")}>{i.label}</span>
                        {badge ? (
                          <span className={cn("rounded-full bg-warn-9 px-1.5 text-[11px] font-semibold leading-4 text-black tabular", collapsed && "absolute -right-0.5 -top-0.5 px-1")} data-testid="pending-badge">
                            {badge}<span className="sr-only"> pending</span>
                          </span>
                        ) : null}
                      </a>
                    );
                    return <li key={i.href}>{collapsed ? <Tooltip content={i.label} side="right">{link}</Tooltip> : link}</li>;
                  })}
                </ul>
              </div>
            ))}
          </div>
          <div className="border-t border-gray-6 px-2 py-2">
            <a href="/#health" className={cn("flex items-center gap-2 rounded-md px-2 py-1.5 text-caption text-gray-11 no-underline hover:bg-gray-4 hover:no-underline", collapsed && "justify-center")}
              aria-label={`System health: ${health.summary}`}>
              <span aria-hidden="true" className={cn("size-2 shrink-0 rounded-full", healthDot)} />
              {!collapsed ? <span className="flex-1 truncate">{health.summary}</span> : null}
              {!collapsed ? <span className="font-mono text-[11px] text-gray-11">v{PRODUCT_VERSION}</span> : null}
            </a>
            <button type="button" onClick={() => void shell.setPref("nav", collapsed ? "expanded" : "collapsed")}
              aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
              className={cn("mt-1 flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-caption text-gray-11 hover:bg-gray-4 hover:text-gray-12", collapsed && "justify-center")}>
              {collapsed ? <ChevronsRight className="size-4" /> : <><ChevronsLeft className="size-4" />Collapse</>}
            </button>
          </div>
        </nav>

        {/* -------------------------------------------------------------- content */}
        <main id="main" tabIndex={-1} className="min-w-0 flex-1 px-4 py-6 outline-none sm:px-6 lg:px-8">
          {children}
          <footer className="mt-10 border-t border-gray-5 pt-4 text-caption text-gray-11">
            Dashboard status is a convenience view; independent verification uses the CLI (<code>agw-verify</code>) on exported bundles with trust roots obtained out of band.
          </footer>
        </main>
      </div>

      <HelpDrawer />
      {paletteUsed ? <CommandPalette nav={nav} /> : null}
      <Shortcuts />
    </div>
  );
}

function Shortcuts() {
  const { shortcutsOpen, setShortcutsOpen } = useShell();
  const rows: [string[], string][] = [
    [["Ctrl", "K"], "Command palette (search, jump, quick actions)"],
    [["g", "o"], "Go to Overview"], [["g", "r"], "Go to Runs"], [["g", "a"], "Go to Approvals"],
    [["g", "e"], "Go to Events"], [["g", "v"], "Go to Verification"], [["g", "p"], "Go to Policies"],
    [["/"], "Focus the table filter"], [["j"], "Next table row"], [["k"], "Previous table row"],
    [["Enter"], "Open the selected row (Shift+Enter: full page)"], [["Esc"], "Close panel or dialog"],
    [["?"], "This sheet"],
  ];
  return (
    <Dialog open={shortcutsOpen} onOpenChange={setShortcutsOpen}>
      <DialogContent title="Keyboard shortcuts" description="Everything is also reachable with Tab and Enter.">
        <dl className="grid grid-cols-[auto_1fr] items-center gap-x-6 gap-y-2.5 px-5 py-4 text-dense">
          {rows.map(([keys, what]) => (
            <div key={what} className="contents">
              <dt className="flex gap-1">{keys.map((k) => <Kbd key={k}>{k}</Kbd>)}</dt>
              <dd className="text-gray-11">{what}</dd>
            </div>
          ))}
        </dl>
        <div className="flex justify-end border-t border-gray-5 px-5 py-3"><Button onClick={() => setShortcutsOpen(false)}><Rows3 />Done</Button></div>
      </DialogContent>
    </Dialog>
  );
}
