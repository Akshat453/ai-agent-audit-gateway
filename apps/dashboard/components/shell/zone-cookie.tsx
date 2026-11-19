"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

/** Tells the server the viewer's time zone (the server runs on UTC). A plain, non-secret cookie;
 *  when it changes, the page re-renders once with the right local times. */
export function ZoneCookie({ current }: { current: string }) {
  const router = useRouter();
  useEffect(() => {
    let zone = "";
    try { zone = Intl.DateTimeFormat().resolvedOptions().timeZone ?? ""; } catch { return; }
    if (!zone || zone === current) return;
    document.cookie = `agw_zone=${encodeURIComponent(zone).replace(/%2F/g, "/")}; Path=/; Max-Age=31536000; SameSite=Lax`;
    router.refresh();
  }, [current, router]);
  return null;
}
