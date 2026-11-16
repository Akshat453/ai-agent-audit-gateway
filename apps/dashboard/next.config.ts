import type { NextConfig } from "next";

// Phase 9 (ADR-0031): the CSP (with a per-request nonce) is set in proxy.ts; the static
// security headers are set here for every response, including /api route handlers.
const nextConfig: NextConfig = {
  // The Docker image (compose profile "ui") builds with AGW_STANDALONE=1; `next start` cannot.
  output: process.env.AGW_STANDALONE === "1" ? "standalone" : undefined,
  outputFileTracingRoot: process.cwd(),
  poweredByHeader: false,
  reactStrictMode: true,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "same-origin" }, // nothing leaks cross-site
          { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
          { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          { key: "Cache-Control", value: "no-store" },
        ],
      },
    ];
  },
};

export default nextConfig;
