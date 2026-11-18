import type { LucideIcon } from "lucide-react";
import { Inbox } from "lucide-react";
import type { ReactNode } from "react";

/** Helpful empty state: what this list is and how data appears in it (§5). */
export function EmptyState({ title, children, icon: Icon = Inbox, action }: { title: string; children?: ReactNode; icon?: LucideIcon; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-12 text-center">
      <div className="mb-3 rounded-full border border-gray-6 bg-gray-2 p-3"><Icon aria-hidden="true" className="size-5 text-gray-11" /></div>
      <p className="text-section font-semibold text-gray-12">{title}</p>
      {children ? <div className="mt-1 max-w-md text-dense text-gray-11">{children}</div> : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}

/** Error state with retry and the request id (§7). */
export function ErrorState({ what, requestId, retryHref }: { what: string; requestId?: string | null; retryHref?: string }) {
  return (
    <div role="alert" className="rounded-md border border-bad-7 bg-bad-3 px-4 py-3 text-dense text-bad-12">
      <p className="font-medium">{what}</p>
      <p className="mt-1 text-bad-11">
        Try again in a moment. If it keeps failing, give an operator the request id
        {requestId ? <> <code className="font-mono">{requestId}</code></> : " from the gateway logs"}.
        {retryHref ? <> <a href={retryHref} className="font-medium text-bad-11 underline">Retry</a></> : null}
      </p>
    </div>
  );
}
