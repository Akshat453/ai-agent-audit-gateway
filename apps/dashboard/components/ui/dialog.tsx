"use client";

import * as DialogPrimitive from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import * as React from "react";

import { cn } from "@/lib/cn";

/** shadcn/ui Dialog on Radix (focus trap + focus restore + Esc, §8). Overlays are the only
 *  place shadows appear. Rendered only after a user opens it, so no SSR inline styles (CSP). */
export const Dialog = DialogPrimitive.Root;
export const DialogTrigger = DialogPrimitive.Trigger;
export const DialogClose = DialogPrimitive.Close;

export function DialogContent({ className, children, title, description, wide, ...props }:
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Content> & { title: React.ReactNode; description?: React.ReactNode; wide?: boolean }) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/40 data-[state=open]:animate-in" />
      <DialogPrimitive.Content
        className={cn(
          "fixed left-1/2 top-[12vh] z-50 w-[calc(100vw-2rem)] -translate-x-1/2 rounded-md border border-gray-6 bg-gray-1 shadow-2xl outline-none data-[state=open]:animate-in",
          wide ? "max-w-2xl" : "max-w-lg",
          className,
        )}
        {...props}
      >
        <div className="flex items-start justify-between gap-4 border-b border-gray-5 px-5 py-4">
          <div>
            <DialogPrimitive.Title className="text-section font-semibold">{title}</DialogPrimitive.Title>
            {description ? <DialogPrimitive.Description className="mt-1 text-dense text-gray-11">{description}</DialogPrimitive.Description> : <DialogPrimitive.Description className="sr-only">{typeof title === "string" ? title : "Dialog"}</DialogPrimitive.Description>}
          </div>
          <DialogPrimitive.Close className="rounded-sm p-1 text-gray-11 hover:bg-gray-4 hover:text-gray-12" aria-label="Close">
            <X className="size-4" />
          </DialogPrimitive.Close>
        </div>
        {children}
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  );
}
