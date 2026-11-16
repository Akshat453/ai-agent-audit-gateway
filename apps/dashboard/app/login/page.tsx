import { Notice, Page } from "@/components/ui";

const ERRORS: Record<string, string> = {
  credentials: "Login failed.",
  origin: "Request rejected (cross-site).",
};

export default async function Login({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const sp = await searchParams;
  return (
    <Page title="Sign in" lead="Approvers, auditors and admins (gateway human accounts). Agent keys cannot sign in here.">
      {sp.error ? <div data-testid="login-error"><Notice kind="bad">{ERRORS[sp.error] ?? "Login failed."}</Notice></div> : null}
      <form method="post" action="/api/auth/login" className="max-w-sm space-y-3 rounded border border-slate-300 bg-white p-4">
        <label className="block text-sm">
          Tenant
          <input name="tenant" required defaultValue="demo" autoComplete="organization" className="mt-1 block w-full rounded border border-slate-400 px-2 py-1" />
        </label>
        <label className="block text-sm">
          Username
          <input name="username" required autoComplete="username" className="mt-1 block w-full rounded border border-slate-400 px-2 py-1" />
        </label>
        <label className="block text-sm">
          Password
          <input name="password" type="password" required autoComplete="current-password" className="mt-1 block w-full rounded border border-slate-400 px-2 py-1" />
        </label>
        <button type="submit" className="rounded bg-blue-800 px-3 py-1 font-semibold text-white">Sign in</button>
      </form>
    </Page>
  );
}
