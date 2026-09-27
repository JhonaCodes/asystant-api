# Operator console

`https://ai.jhonacode.com/admin` is where the operator creates companies, hands
out their API keys and follows their OpenRouter spend. It is server-rendered
HTML without JavaScript, embedded in the same binary as the API.

## Enable it

The console starts when these are set (see [.env.example](../.env.example)):

| Variable | Why |
| --- | --- |
| `OPENROUTER_MANAGEMENT_API_KEY` + `ASYSTANT_MANAGED_ENCRYPTION_KEY` | The managed flow; the encryption key also seals the authenticator secrets |
| `ASYSTANT_PUBLIC_ORIGIN` | The only origin accepted on form submissions, e.g. `https://ai.jhonacode.com`. HTTPS enables HSTS |
| `ASYSTANT_CLIENT_IP_HEADER` (optional) | Behind a proxy, the header it overwrites with the caller address (`CF-Connecting-IP`, `X-Real-IP`). Without it, every caller looks like the proxy |

`/` redirects to `/admin`; the API stays under `/v1` and its contract at
`/openapi.yaml`.

## First administrator

There is no open sign-up. While the database has no administrator, every start
of the service writes a one-time link to the logs:

```text
No administrator yet. Open this link once, before 2026-09-28 10:00 UTC, to set up the /admin console: https://ai.jhonacode.com/admin/setup?token=…
```

The link opens a page where you choose the username and password, scan the QR
code with an authenticator app (or type the key it shows) and confirm with the
code the app displays. You are signed in right away. The link works once and
for 24 hours; a newer start replaces it, and once an administrator exists no
first-run link is issued again.

From the container shell:

```sh
docker exec -it CONTAINER asystant_api admin create maria   # a link for another administrator
docker exec -it CONTAINER asystant_api admin reset jhonacode # recovery
```

`admin reset` is the recovery path when the authenticator or the password is
lost, or the account is locked or stolen: it disables the account and signs it
out everywhere at once, and prints a link that sets a new password and
authenticator. It needs shell access to the server, the same level of trust as
creating the first administrator. There is no email recovery on purpose: it
would let whoever controls the mailbox take over the console. Usernames are
3–64 lowercase letters, digits, dots, hyphens or underscores.

## What it does

- **Overview**: spend confirmed today, money held by live keys, month to date,
  keys issued today, the last 30 days, spend per company against its cap, leases
  that need attention and the health of the background worker.
- **Companies**: create a company with its slug, OpenRouter workspaces, allowed
  models, optional daily cap and contact. Each workspace belongs to one company.
  The cap bounds the sum of the company's daily tenant ceilings.
- **API keys**: label, permissions (issue credentials, manage budgets), expiry
  (30, 90, 180 or 365 days), optional source addresses and rotation. A rotated
  key keeps working for 7 days so the company can deploy without downtime. The
  key is shown once; the server keeps only its SHA-256.
- **Tenants**: the subjects of a tenant, the state of each key of the day and
  the recovery of an uncertain issuance.
- **Suspension**: rejects every API key of the company at once and queues its
  live OpenRouter keys for revocation. Reactivating needs new API keys.
- **Export**: the daily tenant spend of a month as CSV, for all companies or
  one. Cells that a spreadsheet would run as a formula are neutralized.
- **Audit log**: every sign-in, refusal and change, with who, when and from
  where. The database refuses to edit or delete entries.
- **Security**: your sessions (sign out any of them), password change,
  authenticator replacement and the state of the system.

## How it is protected

- **No JavaScript.** `Content-Security-Policy: default-src 'none'; style-src
  'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri
  'none'`, plus `X-Frame-Options: DENY`, `Cache-Control: no-store`,
  `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy: same-origin`.
  Every dynamic value is escaped; meters and charts are SVG attributes, so no
  inline style or script is ever needed.
- **Sign-in**: argon2id password (64 MiB, 3 passes) plus a TOTP code. A code is
  accepted once: its time step is consumed atomically. Unknown usernames cost
  the same as wrong passwords.
- **Lockout**: five failed sign-ins in 15 minutes lock the username and the
  source address. The message never says which part was wrong.
- **Sessions**: 256-bit random token in a `__Host-` cookie (Secure, HttpOnly,
  SameSite=Strict); only its SHA-256 is stored. 30 minutes idle, 8 hours in
  total, revocable from **Security**.
- **Forged requests**: every form carries the session's token, compared in
  constant time, and must come from `ASYSTANT_PUBLIC_ORIGIN`.
- **Step-up**: creating or changing a company, its workspaces, keys, recovery,
  password or authenticator asks for a fresh code even inside a session.
- **Keys**: `ask_live_` + 43 base62 characters (256 random bits) + a
  checksum. The prefix lets secret scanners detect a leak; the checksum rejects
  typos without touching the database.

Recommended at the edge: HTTPS only, and optionally an access gate in front of
`/admin` (for example Cloudflare Access or an address allowlist) as a second
factor that lives outside this service.
