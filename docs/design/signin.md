# Sign-in design (PR 1: the core)

Built from `docs/briefs/2026-09-30-signin-brief.md`, D21 section 6 and D22. Code: `src/ArgusPlatform.psm1`. Sources for the Microsoft claims: `docs/sources/2026-09-30-signin-mail-extracts.md` (P1 to P9).

## In one paragraph

A person opens the module. If they have no session, the server sends them to Microsoft to sign in. Microsoft sends the browser back with a signed "ID token" that says who they are and which app roles they hold. The server checks that token with Microsoft's own validation library, and if every check passes it starts a session held on the server. From then on only the session decides who the person is and what they may do. The app has no client secret, no certificate and no API permissions.

## The flow, step by step

1. **Sign in (`GET <module>/auth/signin`).** The server makes two random values, `state` and `nonce`, and remembers them under a random ID that goes to the browser in a short-lived cookie (`argus_pre`, 10 minutes, `Secure; HttpOnly; SameSite=None`, scoped to `<module>/auth`). It is the only cross-site cookie: Microsoft's reply is a cross-site POST, and only a `SameSite=None` cookie comes along with it. The browser is sent to the tenant's `/oauth2/v2.0/authorize` with `response_type=id_token`, `response_mode=form_post`, `scope=openid profile`, the `state` and the `nonce` (sources P3 to P6).
2. **Callback (`POST <module>/auth/callback`).** Accepts a form with exactly two fields, `id_token` and `state`. Anything else is refused (an `error` post from Microsoft is refused too, and only its short error code is recorded). The remembered `state`/`nonce` is taken out of the server the moment the callback arrives, so each can be used once, even if the attempt then fails.
3. **Validate the token.** See the next section. Any failure refuses the sign-in and writes a `TokenRefused` audit record with a short reason code, never the token.
4. **Session.** A random 256-bit session ID goes in the `argus_session` cookie (`Secure; HttpOnly; SameSite=Lax`, `Path=<module path>`). The server keeps the session (who, name, roles, times, anti-forgery token) under a hash of that ID. A new ID is made at every sign-in. It ends 8 hours after sign-in however busy the person is, or after 30 minutes with no request.
5. **Roles.** Read only from the token's `roles` claim, and only those starting with the module's prefix (`Assure.` or `Assess.`). No claim means no roles. No user list and no role list is kept on the server.
6. **Every later request.** The session cookie is looked up. No session: a page request is sent to sign-in, a change is refused with 401. A state-changing request (anything but GET, HEAD, OPTIONS) also needs the custom header (`X-Argus-Request`) **and** the session's anti-forgery token (`X-Argus-CSRF` header, or a `csrf` form field), on top of the SameSite cookie. The product's handler then gets the session and decides what each role may do.
7. **Sign out (`POST <module>/auth/signout`, with the header and token).** Ends the server session, clears the cookie, and sends the browser to Entra's sign-out endpoint.

## Every token check, in plain English

| Check | What it means | Refusal reason | Tested |
|---|---|---|---|
| Algorithm is RS256 only | `none`, HS256 and anything else are refused before any key is touched, and again inside the library. | `alg_not_allowed` | alg none, HS256 |
| Signature | The token must be signed by one of the tenant's published keys, picked by the token's `kid`. | `bad_signature` | tampered token; right `kid`, wrong key |
| Unknown key | A `kid` we don't hold makes the server fetch the keys again (Microsoft rotates them). It will refetch at most once every 5 minutes, so a flood of bad tokens can't make it hammer Microsoft. | `unknown_kid` | rotation then success; refresh limit |
| Issuer | Must be exactly `https://login.microsoftonline.com/<tenant>/v2.0` for the configured tenant. | `bad_issuer` | wrong issuer |
| Tenant | The `tid` claim must also equal the configured tenant. Single tenant only; "common" is refused at start-up. | `bad_tenant` | wrong tid |
| Audience | `aud` must be this app's client ID. | `bad_audience` | wrong audience |
| Nonce | `nonce` must equal the one made for this sign-in, and it works once. A token from another sign-in, a replay, or no nonce is refused. | `bad_nonce`, `no_pre_signin_cookie` | wrong, missing, other sign-in, replay |
| State | The posted `state` must equal the one made for this sign-in. | `state_mismatch` | wrong state |
| Expiry and start | `exp` and `nbf` are both required, with at most 5 minutes of clock skew. | `token_expired`, `token_not_yet_valid`, `missing_exp`, `missing_nbf` | each, plus the 4-minute skew allowed |
| Who | `oid` must be present. Name comes from `name`, then `preferred_username`. | `missing_oid` | |
| Keys available | The metadata document must name the expected issuer and an `https` key set. | `keys_unavailable` | wrong issuer in metadata |
| Shape | A token over 32 KB, a body over 64 KB, a non-form body, a missing pre-sign-in cookie, a pre-sign-in older than 10 minutes. | `token_too_large`, `malformed_token`, `bad_content_type`, `pre_signin_expired`, ... | several |

The server **never trusts an identity, role or user header** from the proxy or the browser. The code never reads one. The proxy's `X-Forwarded-For` is read for one thing only: the client address in the audit record (the rightmost entry, which the proxy itself added).

## Why a library, and which

Source P8: Microsoft recommends a token validation library rather than checking by hand. The libraries are in `lib/`, pinned by SHA-256 in `lib/manifest.json`:

- `Microsoft.IdentityModel.JsonWebTokens` and `Microsoft.IdentityModel.Protocols.OpenIdConnect` **8.18.0**, plus what they load: `Microsoft.IdentityModel.Tokens`, `.Logging`, `.Abstractions`, `.Protocols`, `System.IdentityModel.Tokens.Jwt` (same version), and `Microsoft.Extensions.Logging.Abstractions` and `Microsoft.Extensions.DependencyInjection.Abstractions` 8.0.0.
- **Maintained by Microsoft** (the identity team; repository `AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet`, MIT licence). The `Microsoft.Extensions.*` pair is Microsoft's .NET team.
- Why 8.18.0 and not the newest (8.23.0): from 8.19.0 the library needs `Microsoft.Bcl.Cryptography` 10.x, which wants a newer `System.Formats.Asn1` than .NET 8 (PowerShell 7.4) ships. I found this the hard way: without that file every token failed as "bad signature". Moving the pin up later is a reviewed one-line change plus a test run on PowerShell 7.4.
- `lib/Fetch-Libs.ps1` downloads each package from nuget.org and refuses any DLL whose SHA-256 differs from the manifest. `Import-PlatformLibraries` checks every file again before loading any, and refuses a changed or missing one (both tested). CI re-fetches and fails if anything under `lib/` differs.

What the library does and what our code does: the library checks the signature, issuer, audience, algorithm and lifetime. Our code does the parts a sign-in handler owns and the validation library does not: choosing the key by `kid` and caching/refreshing the key set (parsed with the OpenID Connect library's metadata classes), the `tid`, `nonce` and `state` checks, `nbf` being present, and the roles.

## Fresh sign-in (item 7)

`Test-PlatformFreshSignIn` says whether the person signed in within the last 15 minutes; the route `<module>/auth/fresh` sends them to Entra again and, when the new token validates, re-reads the roles (a change is audited as `RoleChange`), keeps the original 8-hour limit and gives a new session ID. The new token must be for the same person (`oid`), or it is refused.

**Open item, needs Chris.** The brief says to check Microsoft Learn for which request parameter and which token claim prove a fresh sign-in, and to add the quotes to `docs/sources/`. **I could not do that.** `learn.microsoft.com` is blocked from this build session by the egress policy (the proxy refused the connection), so I have no quotes and I have not added any to the sources file or guessed at them. What the code does meanwhile, clearly marked in `FreshSignInParameters`: it sends `prompt=login` on the forced sign-in and records the server's own time when the new token validates, instead of reading an `auth_time`-style claim. That is only sound if Learn confirms that `prompt=login` forces re-authentication for ID-token sign-in. Until the source is checked, treat "fresh sign-in" as **not verified**. To close it: someone with access fetches the OIDC page's parameter table (`prompt`, and `max_age` if present) and the ID-token claims reference (is there an `auth_time`?), and I add the quotes and adjust.

## Audit

Every `SignIn`, `FreshSignIn`, `SignOut`, `TokenRefused`, `RoleChange` and `SessionExpired` goes to the callback the product gives `New-Platform -Audit`, as a hashtable with `Time`, `Event`, `Oid`, `Name`, `ClientAddress`, `Reason` (and `Roles`, or `Before`/`After` for a role change). A token is never in a record (tested). **It fails closed:** if the callback throws, the sign-in is refused (503) and no session is made (tested).

## Binding

`Start-PlatformServer` refuses any prefix that is not `http://127.0.0.1:<port>/`, before it opens anything (tested for `+`, `*`, `0.0.0.0`, `localhost` and a LAN address). TLS is the reverse proxy's job (D21 section 6). One bad request cannot stop the listener.

## Not in this PR

The test host and Entra setup guide (PR 2), Assure using it (PR 3), local mode (unchanged and untouched: the platform is only used in server mode), the IIS proxy, and anything product-specific.

## Things to watch in PR 2 (real Entra)

- The callback refuses any form field other than `id_token` and `state`, as the brief says. If Entra also posts something harmless such as `session_state`, the first real sign-in will show it as `unexpected_form_field` in the audit log, and we decide then whether to allow that one field.
- Browsers accept `Secure` cookies on `http://localhost`, which the test host uses; Safari does not. Use Edge or Chrome for the test host.

## See it yourself (checklist)

You need PowerShell 7.4+. From the repo root:

1. `pwsh -File lib/Fetch-Libs.ps1` prints `OK` for nine files. (Proves the pinned libraries match NuGet.)
2. `pwsh -Command "Invoke-Pester -Path tests -Output Detailed"` shows 66 passing tests, grouped as Libraries, Configuration, Binding, Sign-in request, ID token validation, Signing keys, Roles, Sessions, Anti-forgery, Spoofed identity headers, Sign out, Fresh sign-in, Audit hook. Read the names: they are the list of checks above.
3. `pwsh -File tools/Invoke-SignInSmoke.ps1` starts the real listener on 127.0.0.1 with a made-up tenant. Look for: (1) a `302` whose `Location` begins `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize` and contains `response_type=id_token`, `response_mode=form_post`, `state=`, `nonce=`, and a `Set-Cookie: argus_pre=...; Secure; HttpOnly; SameSite=None`; (2) a page with no session sent back to sign-in; (3) a POST with no session answered `401`; (4) a path outside the module `404`; (5) a bind to `http://+:8443/` refused.
4. To see a check fail, edit one byte of a file in `lib/` and run step 2: the Libraries tests still pass (they use a copy), but `Import-Module ./src/ArgusPlatform.psm1; Import-PlatformLibraries` throws "does not match its pinned SHA-256". Then `git checkout lib` to undo.
5. Nothing needs Entra yet. The first real sign-in is PR 2.

There are no screenshots in this PR: it has no screen to show. The real-Entra screenshots come in PR 2, from Higate's test tenant.
