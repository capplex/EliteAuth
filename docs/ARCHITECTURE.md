# Architecture

EliteAuth has three main runtime components:

1. **Website** — static HTML, CSS, and JavaScript deployed to Cloudflare Pages, Nginx, or another static host.
2. **Database** — Supabase PostgreSQL stores accounts, applications, licenses, sessions, reset requests, and security events. Row Level Security protects dashboard data.
3. **API Worker** — the Cloudflare Worker performs trusted license activation and session validation using server-only credentials. Responses can be signed with Ed25519.

The SDKs call the Worker API. Private backend credentials must never be embedded in the website or SDKs.
