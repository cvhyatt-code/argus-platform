# argus-platform

The shared platform layer for the Argus modules (Assure and Assess): Entra ID sign-in, sessions, roles and anti-forgery. Nothing here is product-specific. See `docs/design/signin.md` and `docs/briefs/`.

- `src/ArgusPlatform.psm1` the module (PowerShell 7.4+)
- `lib/` the pinned Microsoft token-validation libraries (SHA-256 in `lib/manifest.json`, `lib/Fetch-Libs.ps1` to refetch and check)
- `tests/` Pester tests, no network (keys are generated in memory)
- `tools/Invoke-SignInSmoke.ps1` shows the real listener answering, with no Entra involved

No secret is stored or needed: the sign-in app registration has no client secret, certificate or API permission.
