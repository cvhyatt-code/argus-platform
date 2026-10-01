# Excerpt: D21 (shared server), sections 6 and 9

Copied 2026-09-30 from `cvhyatt-code/defender-suite-assessment/docs/decisions/2026-09-29-shared-server.md` (Accepted, Chris Hyatt, 2026-09-29). Section 6 is now the shared platform layer's design (D22). The full record lives in the Assess repo; this excerpt is for the platform build.

## 6. HTTPS, sign-in and sessions (Chris, 2026-09-29)

**TLS at a reverse proxy.**
- A reverse proxy on the same host terminates HTTPS with the organization's own certificate. **IIS with URL Rewrite is the reference configuration**; the docs will ship an example for it. Another proxy works if it does the same.
- Assess listens on 127.0.0.1 only. Server mode refuses to start bound to anything else. Local mode keeps plain 127.0.0.1 and the per-launch key, as today.
- **The proxy supplies only the client address**, and only for the audit log. Identity comes only from the token. Assess never trusts an identity, role or user header from the proxy or the browser.

**Sign-in (Chris, 2026-09-29).**
- **Choice: OpenID Connect ID-token sign-in with no secret.** The sign-in-only app registration has no API permissions. Entra posts the ID token back to Assess with `form_post`. Assess checks its signature against Entra's published keys, and its issuer (the team's tenant), audience (the app) and nonce.
- **Fallback: authorization code flow with a certificate protected by the service identity.** Allowed under the credential principle (section 3), because the sign-in app has no API permissions: the certificate proves the app to Entra and gives access to nothing in any tenant. Used only if ID-token sign-in stops being supported for web apps.
- **Sources:** checked word for word in `docs/sources/2026-09-30-signin-mail-extracts.md`.

**Roles.** Engineer, approver and viewer are app roles on the sign-in registration, assigned in Entra, read from the token. Assess keeps no user or role list.

**Sessions.**
- A random session ID is held on the server, in a Secure, HttpOnly cookie. Only the sign-in round trip uses a cross-site cookie.
- A session lasts at most 8 hours; 30 minutes idle ends it.
- **Approving an exception needs a sign-in within the last 15 minutes.** That sign-in re-reads the roles.
- **Every state-changing request carries an anti-forgery token**, tied to the session, as well as the SameSite cookie and the existing custom-header check.
- Every change is audited with the signed-in person's Entra object ID and name, and the client address from the proxy.

**Role-removal lag, stated plainly.** Removing a role in Entra takes effect at the person's next sign-in. For ordinary access that can take up to 8 hours (the session limit). For approvals the lag is closed by the 15-minute fresh sign-in, which re-reads the roles.

## 9. Roles (Chris, 2026-09-29)

Roles are Entra app roles on the sign-in registration (section 6). They apply across the whole server, which serves one organization (section 5). Roles limited to some of an organization's tenants are a possible later decision.

| Can change | Engineer | Approver | Viewer |
|---|---|---|---|
| Upload a sealed package; queue and run Reconcile | Yes | No | No |
| Findings: wording, severity, status (closing included) | Yes, audited | No | No |
| Register: notes, and recording a decision made outside the app ("recorded by the assessor") | Yes, audited | No | No |
| Register: approve an entry in the app ("approved in the app by a signed-in approver") | No | Yes, with a sign-in in the last 15 minutes | No |
| Judgment files and client config | Yes, audited | No | No |
| Read the dashboard, register, findings, report, health page and audit log | Yes | Yes | Yes |

- **Nobody changes the audit log.** It's read-only inside the site for every role.
- **Self-approval is blocked on the server, with no override in v1.** No one can approve an entry they last changed, whatever roles they hold. A one-person shop uses local mode (section 1).
- **Decisions recorded outside the app stay allowed, and stay visible.**
- **Engineer changes the director sees.** A severity change, or a finding closed by an engineer, is audited and listed in the director's report the same way as exceptions.
- **Health page flags:**
  - a person holding both the engineer and approver roles;
  - no one with the approver role has signed in. The sign-in app has no API permissions, so the server can't list who holds a role in Entra; it only knows who has signed in.
- **Local mode:** one person holds every role, and every approval is "recorded by the assessor".
