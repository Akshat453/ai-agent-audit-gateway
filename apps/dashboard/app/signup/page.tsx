import type { Metadata } from "next";
import Link from "next/link";

import { Notice } from "@/components/notice";
import { LogoMark } from "@/components/shell/logo";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { PRODUCT_NAME } from "@/lib/brand";
import { signupEnabled } from "@/lib/signup";

export const metadata: Metadata = { title: "Create account" };

const ERRORS: Record<string, string> = {
  taken: "That tenant id is already in use. Choose another one.",
  mismatch: "The two passwords do not match.",
  invalid:
    "Check the fields: tenant id 3–63 characters (a–z, 0–9, -), username lowercase (a–z, 0–9, . _ -), password at least 12 characters.",
  disabled: "Sign-up is turned off on this gateway. Ask an admin to invite you.",
  origin: "Request rejected (cross-site). Open the console from its own address and try again.",
};

export default async function Signup({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const sp = await searchParams;
  const enabled = await signupEnabled();
  return (
    <main id="main" className="flex min-h-screen items-center justify-center bg-gray-2 px-4 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center text-center">
          <LogoMark className="size-10" />
          <h1 className="mt-3 text-title font-semibold tracking-tight">Create account</h1>
          <p className="mt-1 text-dense text-gray-11">
            A new {PRODUCT_NAME} tenant for your organization. You become its first admin and can invite others.
          </p>
        </div>
        {sp.error ? (
          <div data-testid="signup-error">
            <Notice kind="bad">{ERRORS[sp.error] ?? ERRORS.invalid}</Notice>
          </div>
        ) : null}
        {enabled ? (
          <form method="post" action="/api/auth/signup" className="space-y-4 rounded-md border border-gray-6 bg-gray-1 p-5">
            <div>
              <Label htmlFor="organization">Organization name</Label>
              <Input id="organization" name="organization" required maxLength={200} autoComplete="organization" className="mt-1.5" autoFocus />
            </div>
            <div>
              <Label htmlFor="tenant">Tenant id</Label>
              <Input
                id="tenant"
                name="tenant"
                required
                pattern="[a-z0-9][a-z0-9\-]{2,62}"
                placeholder="acme"
                className="mt-1.5"
                aria-describedby="tenant-hint"
              />
              <p id="tenant-hint" className="mt-1 text-caption text-gray-11">You type this when you sign in. Lowercase letters, digits and dashes.</p>
            </div>
            <div>
              <Label htmlFor="username">Username</Label>
              <Input id="username" name="username" required pattern="[a-z0-9][a-z0-9._\-]{0,63}" autoComplete="username" className="mt-1.5" />
            </div>
            <div>
              <Label htmlFor="password">Password</Label>
              <Input id="password" name="password" type="password" required minLength={12} autoComplete="new-password" className="mt-1.5" aria-describedby="password-hint" />
              <p id="password-hint" className="mt-1 text-caption text-gray-11">At least 12 characters.</p>
            </div>
            <div>
              <Label htmlFor="confirm">Confirm password</Label>
              <Input id="confirm" name="confirm" type="password" required minLength={12} autoComplete="new-password" className="mt-1.5" />
            </div>
            <Button type="submit" variant="primary" size="lg" className="w-full">Create account</Button>
          </form>
        ) : (
          <div data-testid="signup-disabled">
            <Notice kind="info">{ERRORS.disabled}</Notice>
          </div>
        )}
        <p className="mt-4 text-center text-dense text-gray-11">
          Already have an account?{" "}
          <Link href="/login" className="font-medium text-brand-11">
            Sign in
          </Link>
        </p>
      </div>
    </main>
  );
}
