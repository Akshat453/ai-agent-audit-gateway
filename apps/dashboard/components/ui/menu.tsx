"use client";

import * as Menu from "@radix-ui/react-dropdown-menu";
import * as React from "react";

import { cn } from "@/lib/cn";

export const DropdownMenu = Menu.Root;
export const DropdownMenuTrigger = Menu.Trigger;
export const DropdownMenuGroup = Menu.Group;
export const DropdownMenuRadioGroup = Menu.RadioGroup;

export function DropdownMenuContent({ className, ...props }: React.ComponentPropsWithoutRef<typeof Menu.Content>) {
  return (
    <Menu.Portal>
      <Menu.Content
        sideOffset={6}
        className={cn("z-50 min-w-48 rounded-md border border-gray-6 bg-gray-1 p-1 text-dense shadow-xl data-[state=open]:animate-in", className)}
        {...props}
      />
    </Menu.Portal>
  );
}

const item = "flex cursor-default select-none items-center gap-2 rounded-sm px-2 py-1.5 text-gray-12 outline-none data-[highlighted]:bg-gray-4 data-[disabled]:opacity-50 [&_svg]:size-4 [&_svg]:text-gray-11";

export function DropdownMenuItem({ className, ...props }: React.ComponentPropsWithoutRef<typeof Menu.Item>) {
  return <Menu.Item className={cn(item, className)} {...props} />;
}

export function DropdownMenuRadioItem({ className, children, ...props }: React.ComponentPropsWithoutRef<typeof Menu.RadioItem>) {
  return (
    <Menu.RadioItem className={cn(item, "pl-7 relative", className)} {...props}>
      <Menu.ItemIndicator className="absolute left-2 inline-flex size-3 items-center justify-center">
        <span className="size-1.5 rounded-full bg-brand-9" />
      </Menu.ItemIndicator>
      {children}
    </Menu.RadioItem>
  );
}

export function DropdownMenuLabel({ className, ...props }: React.ComponentPropsWithoutRef<typeof Menu.Label>) {
  return <Menu.Label className={cn("px-2 py-1.5 text-caption font-medium text-gray-11", className)} {...props} />;
}

export function DropdownMenuSeparator() {
  return <Menu.Separator className="my-1 h-px bg-gray-5" />;
}
