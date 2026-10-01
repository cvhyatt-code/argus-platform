# Decision record: one Argus install, separate modules

Status: Accepted (Chris Hyatt, 2026-09-29)
Applies to: Argus Assure (`control-assurance-radar`) and Argus Assess for Defender (`defender-suite-assessment`). Commit this same file to both repos under `docs/decisions/`. In Assess it is D22.
Not in scope: Argus Scout. It stays a separate product, because it runs inside the OT environment.

## Why

A customer who buys both Assure and Assess must get one server, one website, one sign-in, one set of roles and one audit log. They must never get two answers to the same question. A customer who buys one product gets only that one. The front door and sign-in are the expensive, security-sensitive parts, so they are built once.

## Decisions

1. **One install per customer.** A shared platform layer provides the front door, sign-in, roles, data root, audit log and email. Assure and Assess plug into it as modules.
2. **Separate modules, separate repos, separate releases.** The repos are not merged. Each keeps its own tests, CI, version and changelog.
3. **Shared platform code lives in its own repo** (proposed name `argus-platform`), vendored into each product at a tag, the same way the brand kit is. Nothing in it is product-specific.
4. **Licensed per module.** For now the licence is a setting in the data root that turns a module on or off. Enforcement (signed keys, expiry) waits until there is a second customer. A module that is off shows nothing and collects nothing.
5. **One owner per fact.**
   - Assess owns Defender configuration: baselines, exceptions, findings and the exception report.
   - Assure owns the director's view, the tracker and recurring obligations.
   - When Assure shows something Assess produced, it displays Assess's answer as-is and never recalculates it. Assure reads Assess output through a defined, versioned file (the exception report), not Assess's internals.
   - Overlap to resolve before Assure Phase 4: Assure's Defender tile (onboarding and antivirus state) versus Assess's Defender configuration. Write down which facts each owns.
6. **Sign-in is Entra ID, done by the app, as D21 section 6 describes.** ID-token sign-in with no client secret, with the certificate code flow as the fallback. This supersedes the family plan's "Windows Authentication at IIS with the user passed in a header". IIS does TLS, logging and request limits, and reverse-proxies to the modules on 127.0.0.1. It does not authenticate.
   - Reason: it works for any Microsoft 365 customer, not only for domain-joined servers.
   - The server needs outbound HTTPS to Entra sign-in endpoints.
7. **One app registration per install, used for sign-in only** (no API permissions). App roles are prefixed by module:
   - Assure: `Assure.Viewer`, `Assure.Editor` (updates tracker items), `Assure.Admin`
   - Assess: `Assess.Viewer`, `Assess.Engineer`, `Assess.Approver`
   - Roles come from the ID token. The customer assigns users or groups to roles in Entra. The known limit from D21 stays: the server sees who has signed in, not everyone who was assigned a role.
   - Tenant data collection uses separate, read-only app identities (D21 section 3), never the sign-in app.
8. **Routing:** one hostname, with modules on paths (`/assure`, `/assess`), and IIS URL Rewrite sends each path to its module's loopback port. Each module keeps its own session cookie, scoped to its path. Entra single sign-on makes the second sign-in silent, so users don't notice. A single shared session is a later decision.
9. **Local single-user mode stays** for both products (D21 section 1). A consultant or a one-person shop runs a module on its own, with no server.

## What changes in existing documents

- Family plan, Phase 4: the Windows Authentication and header-passing design is replaced by item 6.
- D21: unchanged. Its sign-in, roles and IIS design become the platform layer's design, not Assess-only.
- Assure Phase 4 build order: platform repo (front door, sign-in, roles, audit log), then SQLite tracker, then scheduled collectors.

## Open, decided later

- Licence enforcement method.
- A single shared session across modules.
- Per-tenant roles (for customers with several tenants).
