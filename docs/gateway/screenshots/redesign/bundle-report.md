# Bundle report (gzipped first-load JS per route)

Measured by `apps/dashboard/scripts/bundle-report.mjs` in Chromium against the production build (compose profile "ui"). Each script the page loaded, gzip level 9.

| Route | JS files | JS raw (KB) | JS gzip (KB) | Budget 300 KB |
|---|---:|---:|---:|---|
| `/login` | 9 | 641.2 | 198.0 | ok |
| `/` | 11 | 1004.4 | 301.5 | **OVER** |
| `/approvals` | 11 | 709.5 | 217.6 | ok |
| `/approvals/[id]` | 10 | 646.1 | 200.1 | ok |
| `/actions/[id]` | 10 | 645.3 | 199.8 | ok |
| `/events/[id]` | 10 | 654.8 | 202.8 | ok |
| `/runs` | 9 | 641.2 | 198.0 | ok |
| `/evidence` | 9 | 641.2 | 198.0 | ok |
| `/epochs` | 9 | 641.2 | 198.0 | ok |
| `/verification` | 9 | 641.2 | 198.0 | ok |
| `/policies` | 9 | 641.2 | 198.0 | ok |
| `/incidents` | 9 | 641.2 | 198.0 | ok |
