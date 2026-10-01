# Build brief: argus-platform, part 1 — Entra sign-in, roles and sessions

Owner: Chris Hyatt (Higate Ventures, LLC). Written 2026-09-30.
Repo: `cvhyatt-code/argus-platform` (new, private). Shared by Argus Assure and Argus Assess (D22).
Read first (copied into this repo so you don't need the others):
- `docs/decisions/2026-09-29-one-install-separate-modules.md` (D22): one install, modules on paths, one sign-in app registration, roles prefixed by module.
- `docs/decisions/2026-09-29-shared-server-sections-6-9.md` (D21, sections 6 and 9): HTTPS, sign-in, sessions and roles. This brief builds section 6 for the platform.
- `docs/sources/2026-09-30-signin-mail-extracts.md`: the Microsoft Learn quotes for ID-token sign-in, checked word for word. **Its section "What the sources change in D21" applies here**, in particular: ID tokens must be enabled on the app registration, and tokens are validated with a library, not by hand.
- For PR 3 only, in `cvhyatt-code/control-assurance-radar`: `src/Radar.Local.psm1` (the local web service and its token checks) and `docs/design/tracker-sqlite.md` (what sign-in needs from the tracker).

## Why

Casey's team will use one shared Assure on a RYAM server. Today Assure runs on one PC with an Admin/Read-only switch anyone can click, and names are recorded as the Windows user. On a server that isn't good enough: the director needs to know that a tracker change or an approval was made by a real, signed-in person with the right role. Sign-in is the expensive, security-sensitive part, so it's built once here and both products use it (D22).

## 0. How to work

- **Three PRs, in order.** Stop after each for Chris's review. Don't merge.
- **PowerShell 7.4+, the same style as the products** (the local services are PowerShell `HttpListener`). One module, `src/ArgusPlatform.psm1` (split into more files if it helps), with Pester tests and CI on Windows and Linux, copied from Assure's CI.
- **Nothing product-specific in this repo.** Module names and role names come from configuration.
- **Vendored at a tag** into each product (`platform/` folder, with a `PLATFORM_VERSION` file), the same way the brand kit is vendored. PR 3 does the first vendoring into Assure.
- **Local mode must keep working unchanged** in both products (D21 section 1): no sign-in, the per-launch key, one person with every role.
- **Show Chris, don't just tell him:** screenshots of the sign-in flow from Higate's test tenant (no client data), a see-it-yourself checklist, and exact setup steps he can follow in the Entra admin center.
- **No client names** anywhere. The test tenant is Higate's own.
- **No secrets, ever.** No client secret, no token, no key in the repo, in config files or in logs.

## 1. PR 1: sign-in core (no product changes)

**Flow: OpenID Connect ID-token sign-in, `form_post`, no client secret** (D21 section 6).
1. **Sign in:** redirect to the tenant's `/oauth2/v2.0/authorize` with `response_type=id_token`, `response_mode=form_post`, `scope=openid profile`, a random `state` and a random `nonce`, both bound to a short-lived pre-sign-in cookie (the only cross-site cookie; `SameSite=None; Secure; HttpOnly`, 10 minutes).
2. **Callback:** accept the POSTed `id_token` and `state`. Refuse anything else.
3. **Validate the ID token with Microsoft's token validation library, not by hand** (sources P8): `Microsoft.IdentityModel.JsonWebTokens` and `Microsoft.IdentityModel.Protocols.OpenIdConnect`, loaded from PowerShell 7, shipped inside the repo and pinned by SHA-256 exactly the way Assure ships its SQLite library (`lib/` plus a fetch-and-check script and a loader that refuses a changed file). Recommend the versions and say who maintains them. Configure it so that it checks all of the following, and test each one, or refuse the sign-in:
   - signature against the tenant's published signing keys (from the OpenID metadata document), cached, refreshed when an unknown `kid` appears, with a limit on how often it refreshes;
   - `iss` is the configured tenant's v2 issuer, and `tid` matches the configured tenant (single tenant only);
   - `aud` is the app's client ID;
   - `nonce` matches the one bound to this sign-in, and is used once;
   - `exp` and `nbf` with at most 5 minutes' clock skew;
   - algorithm is RS256 only; `none` and anything else are refused.
4. **Session:** a random session ID in a `Secure; HttpOnly; SameSite=Lax` cookie scoped to the module's path (D22 item 8); the session itself held on the server. At most 8 hours, and 30 minutes idle ends it.
5. **Roles** come only from the token's `roles` claim, filtered to the module's own prefix (`Assure.*` or `Assess.*`). No user or role list is kept. **The server never trusts an identity, role or user header** from the proxy or the browser.
6. **Anti-forgery:** every state-changing request needs a token tied to the session, as well as the SameSite cookie and the existing custom-header check.
7. **Fresh sign-in for sensitive actions:** a helper that says whether the person signed in within the last 15 minutes, and a route that forces a fresh sign-in and re-reads the roles. **Check against Microsoft Learn which request parameter and which token claim prove a fresh sign-in** (for example `max_age` and `auth_time`, or `prompt=login`), add the quotes to `docs/sources/` checked word for word the way the existing sources file was, and use what the source supports. If Learn doesn't support it for ID-token sign-in, say so and stop for Chris.
8. **Sign out:** ends the server session and sends the browser to Entra's sign-out endpoint.
9. **Audit hook:** every sign-in, sign-out, refused token (with the reason, never the token) and role change seen at sign-in goes to an audit callback the product supplies, with the Entra object ID (`oid`), display name and client address.
10. **Bind to 127.0.0.1 only** in server mode, and refuse to start otherwise. The client address for the audit log may come from the proxy's `X-Forwarded-For`, and only for the audit log.

**Tests (no network):** a test key pair and a fake metadata document and key set under `tests/fixtures/`. Cover: a good token; a bad signature; wrong issuer, tenant, audience; expired; not yet valid; wrong or reused nonce; wrong state; `alg: none`; an unknown `kid` then a refresh; a missing `roles` claim (no roles, read nothing); roles from another module ignored; session expiry (absolute and idle); anti-forgery missing or wrong; a spoofed identity header ignored.

**Done when:** CI is green on both runners, the design doc `docs/design/signin.md` explains the flow and every check in plain English, and the sources file is committed. Stop for Chris.

## 2. PR 2: a test host and Higate's tenant

- A tiny test host (`tools/Start-SignInTestHost.ps1`) that serves one page on `http://localhost:<port>/test` showing, after sign-in: the name, the object ID, the roles, the session's age, and a button that needs a fresh sign-in. Entra allows `http://localhost` redirect URIs for testing; the real server uses HTTPS through IIS (D21 section 6).
- **Setup doc for Chris** (`docs/setup-entra.md`), click by click in the Entra admin center, for a **sign-in-only app registration**:
  - single tenant; web platform; redirect URI(s);
  - **ID tokens (used for implicit and hybrid flows) ticked, access tokens not ticked** (sources P1);
  - **no API permissions, no client secret, no certificate**;
  - app roles from a committed file (`config/app-roles.json`): `Assure.Viewer`, `Assure.Editor`, `Assure.Admin`, `Assess.Viewer`, `Assess.Engineer`, `Assess.Approver`, each with a one-line description;
  - "Assignment required" turned on, so only assigned people can sign in;
  - assigning people or groups to roles;
  - what to copy into the product's config (tenant ID, client ID, redirect URI) — nothing secret.
- A small **setup check** script that reads the product's sign-in config and the tenant's public metadata, and prints what's wrong (wrong tenant ID, redirect URI mismatch) without signing in as an admin.
- **Screenshots** of each step from Higate's tenant, and of the test page for a Viewer, an Editor and someone with no role.

**Done when:** Chris has followed `docs/setup-entra.md` in Higate's tenant and signed in to the test host with two different roles. Stop for Chris.

## 3. PR 3: Assure uses it (server mode), in `control-assurance-radar`

This PR is in the Assure repo. It vendors `argus-platform` at its tag.

- **A deployment setting: local or server.** Local is today's behaviour, untouched. Server turns on sign-in and refuses to start without a valid sign-in config.
- **Roles in server mode:**

  | Can do | Viewer | Editor | Admin |
  |---|---|---|---|
  | Read every page | Yes | Yes | Yes |
  | Tracker: create, update, close items; add updates | No | Yes | Yes |
  | Obligations: Mark done (attested) | No | Yes | Yes |
  | Exceptions: exclude or restore (simple mode) | No | No | Yes |
  | Settings, thresholds, layout, pins, client name | No | No | Yes |

  The **Admin / Read-only switch is hidden in server mode**; what you can do comes from your role. Pages show what's read-only for you, rather than failing on save.
- **Who did it:** every tracker change, Mark done and setting change records the display name and the Entra object ID (the tracker's `…EntraOid` columns already exist) instead of the Windows user.
- **Audit:** sign-ins and refusals go to `audit.jsonl`.
- **Tests** in both modes; the fixture suite passes in local mode unchanged.
- **Screenshots** from the test host setup in Higate's tenant: a Viewer seeing the Tracker read-only, an Editor saving an item with their name recorded, an Admin in Settings.

**Done when:** CI is green, local mode is unchanged at the client, and Chris has signed in to Assure in server mode on his own PC against Higate's tenant with each role. Stop for Chris.

## Not in this brief (next briefs)

- **The server itself:** IIS reverse proxy config, scheduled tasks and service accounts, startup checks, the health page (D21 sections 6 and 7). Needs the RYAM server and FrameFlow timing.
- **RYAM's own app registration**, which becomes a second configuration once this works in Higate's tenant.
- **Assess in server mode** (upload, Reconcile on the server). Assess is feature-frozen; it comes later.
- **The people list** becomes Entra-backed later: a person is matched to their Entra account by email (Assess 0.34.0 stores it).
- **Email** (D21 section 8) and **code signing** (on the punchlist).
