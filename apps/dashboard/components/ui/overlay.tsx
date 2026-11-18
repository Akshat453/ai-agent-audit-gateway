"use client";

import * as PopoverPrimitive from "@radix-ui/react-popover";
import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import * as React from "react";

import { cn } from "@/lib/cn";

export const TooltipProvider = TooltipPrimitive.Provider;

/** Hover/focus tooltip. Text only (escaped by React). */
export function Tooltip({ content, children, side = "top" }: { content: React.ReactNode; children: React.ReactNode; side?: "top" | "bottom" | "left" | "right" }) {
  if (!content) return <>{children}</>;
  return (
    <TooltipPrimitive.Root delayDuration={250}>
      <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
      <TooltipPrimitive.Portal>
        <TooltipPrimitive.Content side={side} sideOffset={6}
          className="z-50 max-w-xs rounded-md border border-gray-6 bg-gray-12 px-2.5 py-1.5 text-caption text-gray-1 shadow-lg data-[state=delayed-open]:animate-in">
          {content}
        </TooltipPrimitive.Content>
      </TooltipPrimitive.Portal>
    </TooltipPrimitive.Root>
  );
}

export const Popover = PopoverPrimitive.Root;
export const PopoverTrigger = PopoverPrimitive.Trigger;

export function PopoverContent({ className, ...props }: React.ComponentPropsWithoutRef<typeof PopoverPrimitive.Content>) {
  return (
    <PopoverPrimitive.Portal>
      <PopoverPrimitive.Content sideOffset={6}
        className={cn("z-50 rounded-md border border-gray-6 bg-gray-1 p-3 text-dense shadow-xl outline-none data-[state=open]:animate-in", className)}
        {...props} />
    </PopoverPrimitive.Portal>
  );
}
