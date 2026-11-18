"use client";

import { useRouter } from "next/navigation";
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

import { toast } from "@/components/ui/toast";

export type ShellPrefs = { theme: "light" | "dark"; density: "comfortable" | "compact"; tz: "utc" | "local"; nav: "expanded" | "collapsed" };

type Ctx = {
  csrf: string;
  prefs: ShellPrefs;
  setPref: <K extends keyof ShellPrefs>(key: K, value: ShellPrefs[K]) => Promise<void>;
  help: string | null;
  openHelp: (topic: string) => void;
  closeHelp: () => void;
  paletteOpen: boolean;
  setPaletteOpen: (open: boolean) => void;
  shortcutsOpen: boolean;
  setShortcutsOpen: (open: boolean) => void;
};

const ShellContext = createContext<Ctx | null>(null);

const HTML_CLASS: Record<string, (v: string, cl: DOMTokenList) => void> = {
  theme: (v, cl) => { cl.toggle("dark", v === "dark"); cl.toggle("light", v !== "dark"); },
  density: (v, cl) => cl.toggle("density-compact", v === "compact"),
};

export function ShellProvider({ csrf, initialPrefs, children }: { csrf: string; initialPrefs: ShellPrefs; children: ReactNode }) {
  const router = useRouter();
  const [prefs, setPrefs] = useState(initialPrefs);
  const [help, setHelp] = useState<string | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);

  /** Preferences are harmless, so the UI updates optimistically (§7), then persists through
   *  POST /api/prefs (same-origin + CSRF). On failure it reverts and says so. */
  const setPref = useCallback(async <K extends keyof ShellPrefs>(key: K, value: ShellPrefs[K]) => {
    const before = prefs[key];
    setPrefs((p) => ({ ...p, [key]: value }));
    HTML_CLASS[key]?.(String(value), document.documentElement.classList);
    const body = new FormData();
    body.set("csrf", csrf);
    body.set("key", key);
    body.set("value", String(value));
    const r = await fetch("/api/prefs", { method: "POST", body, credentials: "same-origin" }).catch(() => null);
    if (!r || !r.ok) {
      setPrefs((p) => ({ ...p, [key]: before }));
      HTML_CLASS[key]?.(String(before), document.documentElement.classList);
      toast("Preference not saved", { tone: "bad", description: "Reload the page and try again." });
      return;
    }
    if (key === "tz") router.refresh(); // server-rendered times use it
  }, [csrf, prefs, router]);

  const value = useMemo<Ctx>(() => ({
    csrf, prefs, setPref, help, openHelp: setHelp, closeHelp: () => setHelp(null),
    paletteOpen, setPaletteOpen, shortcutsOpen, setShortcutsOpen,
  }), [csrf, prefs, setPref, help, paletteOpen, shortcutsOpen]);
  return <ShellContext.Provider value={value}>{children}</ShellContext.Provider>;
}

export function useShell(): Ctx {
  const c = useContext(ShellContext);
  if (!c) throw new Error("useShell outside ShellProvider");
  return c;
}

export function useOptionalShell(): Ctx | null {
  return useContext(ShellContext);
}
