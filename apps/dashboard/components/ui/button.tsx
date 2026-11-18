import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";

import { cn } from "@/lib/cn";

/** shadcn/ui Button, re-tokened: one brand accent (iris) for primary, status colors only for
 *  intent (approve = ok, reject/danger = bad). 6 px radius, 1 px borders, no shadows.
 *  Solid steps/text per theme are chosen for WCAG AA (>= 4.5:1, checked by axe in both themes). */
export const buttonVariants = cva(
  "inline-flex shrink-0 cursor-pointer items-center justify-center gap-1.5 whitespace-nowrap rounded-md border text-dense font-medium no-underline transition-colors duration-150 ease-out hover:no-underline disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        primary: "border-transparent bg-brand-9 text-white hover:bg-brand-10",
        secondary: "border-gray-7 bg-gray-1 text-gray-12 hover:bg-gray-3 hover:border-gray-8",
        ghost: "border-transparent bg-transparent text-gray-11 hover:bg-gray-4 hover:text-gray-12",
        approve: "border-transparent bg-ok-11 text-white hover:bg-ok-12 dark:bg-ok-9 dark:text-gray-1 dark:hover:bg-ok-11",
        danger: "border-transparent bg-bad-11 text-white hover:bg-bad-12 dark:bg-bad-10 dark:text-gray-1 dark:hover:bg-bad-11",
        "danger-outline": "border-bad-7 bg-gray-1 text-bad-11 hover:bg-bad-3",
      },
      size: { sm: "h-7 px-2.5", md: "h-8 px-3", lg: "h-9 px-4 text-body", icon: "size-8 p-0" },
    },
    defaultVariants: { variant: "secondary", size: "md" },
  },
);

export type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> &
  VariantProps<typeof buttonVariants> & { asChild?: boolean };

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, type, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp
        ref={ref}
        className={cn(buttonVariants({ variant, size }), className)}
        {...(asChild ? {} : { type: type ?? "button" })}
        {...props}
      />
    );
  },
);
Button.displayName = "Button";
