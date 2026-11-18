import type { Metadata } from "next";
import Link from "next/link";

import { Notice } from "@/components/notice";
import { LogoMark } from "@/components/shell/logo";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { PRODUCT_NAME } from "@/lib/brand";
import { safeNext } from "@/lib/next";
import { signupEnabled } from "@/lib/signup";

export const metadata: Metadata = { title: "Sign in" };

/** One message for unknown user, wrong password and wrong tenant: no user enumeration. */
const ERRORS: Record<string, string> = {
  credentials: "Login failed. Check the tenant, username and password, then try again.",
  origin: "Request rejected (cross-site). Open the console from its own address and sign in again.",
};

export default async function Login({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const sp = await searchParams;
  const next = safeNext(sp.next, "/");
  const canSignUp = await signupEnabled();
  return (
    <main id="main" className="flex min-h-screen items-center justify-center bg-gray-2 px-4 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center text-center">
          <LogoMark className="size-10" />
          <h1 className="mt-3 text-title font-semibold tracking-tight">Sign in</h1>
          <p className="mt-1 text-dense text-gray-11">{PRODUCT_NAME}: approvers, auditors and admins. Agent keys cannot sign in here.</p>
        </div>
        {sp.error ? <div data-testid="login-error"><Notice kind="bad">{ERRORS[sp.error] ?? ERRORS.credentials}</Notice></div> : null}
        <form method="post" action="/api/auth/login" className="space-y-4 rounded-md border border-gray-6 bg-gray-1 p-5">
          {next !== "/" ? <input type="hidden" name="next" value={next} /> : null}
          <div>
            <Label htmlFor="tenant">Tenant</Label>
            <Input id="tenant" name="tenant" required autoComplete="organization" className="mt-1.5" />
          </div>
          <div>
            <Label htmlFor="username">Username</Label>
            <Input id="username" name="username" required autoComplete="username" className="mt-1.5" autoFocus />
          </div>
          <div>
            <Label htmlFor="password">Password</Label>
            <Input id="password" name="password" type="password" required autoComplete="current-password" className="mt-1.5" />
          </div>
          <Button type="submit" variant="primary" size="lg" className="w-full">Sign in</Button>
        </form>
        {canSignUp ? (
          <p className="mt-4 text-center text-dense text-gray-11">
            New here?{" "}
            <Link href="/signup" className="font-medium text-brand-11" data-testid="signup-link">
              Create an account
            </Link>
          </p>
        ) : null}
        <p className="mt-4 text-center text-caption text-gray-11">Sessions use an httpOnly, SameSite=Strict cookie. Nothing is stored in the browser.</p>
      </div>
    </main>
  );
}
