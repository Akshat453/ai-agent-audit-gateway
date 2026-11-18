"use client";

import { Command } from "cmdk";
import {
  ArrowRight, CornerDownLeft, FileSearch, Hash, Keyboard, Moon, ShieldCheck, Sun, type LucideIcon,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { NAV_ICONS } from "@/components/shell/nav-icons";
import { useShell } from "@/components/shell/context";
import { Kbd } from "@/components/ui/input";
import type { NavGroup } from "@/lib/nav";

type Hit = { kind: string; id: string; label: string; href: string };

/** Ctrl/Cmd K (§4): jump to any page, look up an action / run / event / approval id or a hash
 *  prefix (gateway-side search through /api/search), and quick actions. cmdk renders inside a
 *  Radix dialog, only after the user opens it (no server-rendered inline styles; CSP). */
export function CommandPalette({ nav }: { nav: NavGroup[] }) {
  const { paletteOpen, setPaletteOpen, prefs, setPref, setShortcutsOpen } = useShell();
  const router = useRouter();
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<Hit[]>([]);
  const [searching, setSearching] = useState(false);

  useEffect(() => {
    const term = q.trim();
    const lookup = /^[0-9a-f-]{36}$/i.test(term) || /^(0x)?[0-9a-f]{8,}$/i.test(term);
    if (!lookup) {
      setHits([]);
      return;
    }
    setSearching(true);
    const ctl = new AbortController();
    const id = setTimeout(async () => {
      try {
        const r = await fetch(`/api/search?q=${encodeURIComponent(term)}`, { signal: ctl.signal, credentials: "same-origin" });
        setHits(r.ok ? ((await r.json()) as Hit[]) : []);
      } catch {
        /* aborted */
      } finally {
        setSearching(false);
      }
    }, 180);
    return () => { ctl.abort(); clearTimeout(id); };
  }, [q]);

  const go = (href: string) => {
    setPaletteOpen(false);
    setQ("");
    router.push(href);
  };
  const item = "flex cursor-pointer items-center gap-2.5 rounded-sm px-2.5 py-2 text-dense text-gray-12 data-[selected=true]:bg-gray-4 [&_svg]:size-4 [&_svg]:text-gray-11";
  const heading = "px-2.5 pb-1 pt-2 text-caption font-medium text-gray-11 [&_[cmdk-group-heading]]:pb-1";

  return (
    <Command.Dialog
      open={paletteOpen}
      onOpenChange={(o) => { setPaletteOpen(o); if (!o) setQ(""); }}
      label="Command palette"
      shouldFilter={hits.length === 0}
      overlayClassName="fixed inset-0 z-50 bg-black/40"
      contentClassName="fixed left-1/2 top-[14vh] z-50 w-[calc(100vw-2rem)] max-w-xl -translate-x-1/2 overflow-hidden rounded-md border border-gray-6 bg-gray-1 shadow-2xl data-[state=open]:animate-in"
    >
      <div className="flex items-center gap-2 border-b border-gray-5 px-3">
        <FileSearch aria-hidden="true" className="size-4 text-gray-11" />
        <Command.Input value={q} onValueChange={setQ} placeholder="Search pages, or paste an id / hash prefix…"
          className="h-12 flex-1 bg-transparent text-body outline-none placeholder:text-gray-10" />
        <Kbd>Esc</Kbd>
      </div>
      <Command.List className="max-h-[min(60vh,420px)] overflow-y-auto p-1.5">
        <Command.Empty className="px-3 py-6 text-center text-dense text-gray-11">
          {searching ? "Searching…" : "No match. Paste a full id (UUID) or at least 8 hex characters of a hash."}
        </Command.Empty>
        {hits.length ? (
          <Command.Group heading="Matches" className={heading}>
            {hits.map((h) => (
              <Command.Item key={`${h.kind}-${h.id}`} value={`${h.label} ${h.id}`} onSelect={() => go(h.href)} className={item}>
                <Hash />
                <span className="flex-1 truncate">{h.label}</span>
                <span className="font-mono text-caption text-gray-11">{h.id.slice(0, 8)}…</span>
              </Command.Item>
            ))}
          </Command.Group>
        ) : null}
        <Command.Group heading="Quick actions" className={heading}>
          <Action icon={ShieldCheck} label="Review pending approvals" onSelect={() => go("/approvals?state=PENDING")} className={item} />
          <Action icon={ShieldCheck} label="Run verification" onSelect={() => go("/verification#run")} className={item} />
          <Action icon={prefs.theme === "dark" ? Sun : Moon} label={`Switch to ${prefs.theme === "dark" ? "light" : "dark"} theme`}
            onSelect={() => { setPaletteOpen(false); void setPref("theme", prefs.theme === "dark" ? "light" : "dark"); }} className={item} />
          <Action icon={Keyboard} label="Keyboard shortcuts" onSelect={() => { setPaletteOpen(false); setShortcutsOpen(true); }} className={item} />
        </Command.Group>
        {nav.map((g) => (
          <Command.Group key={g.label ?? "main"} heading={g.label ?? "Go to"} className={heading}>
            {g.items.map((i) => {
              const Icon = NAV_ICONS[i.icon] ?? ArrowRight;
              return (
                <Command.Item key={i.href} value={`go ${i.label}`} onSelect={() => go(i.href)} className={item}>
                  <Icon />
                  <span className="flex-1">{i.label}</span>
                  {i.key ? <span className="flex gap-1"><Kbd>g</Kbd><Kbd>{i.key}</Kbd></span> : null}
                </Command.Item>
              );
            })}
          </Command.Group>
        ))}
      </Command.List>
      <div className="flex items-center gap-3 border-t border-gray-5 px-3 py-2 text-caption text-gray-11">
        <span className="inline-flex items-center gap-1"><CornerDownLeft className="size-3" />open</span>
        <span className="inline-flex items-center gap-1"><Kbd>↑</Kbd><Kbd>↓</Kbd>move</span>
      </div>
    </Command.Dialog>
  );
}

function Action({ icon: Icon, label, onSelect, className }: { icon: LucideIcon; label: string; onSelect: () => void; className: string }) {
  return (
    <Command.Item value={label} onSelect={onSelect} className={className}>
      <Icon />
      <span className="flex-1">{label}</span>
    </Command.Item>
  );
}
