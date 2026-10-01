#requires -Version 7.4
<#
  ArgusPlatform: Entra ID-token sign-in, sessions, roles and anti-forgery for the Argus modules.
  Nothing here is product-specific: the module path and role prefix come from configuration.
  No secret is read, stored or logged. Design and every check: docs/design/signin.md
#>
Set-StrictMode -Version Latest

$script:LibRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'lib'
$script:PreCookie = 'argus_pre'
$script:SessionCookie = 'argus_session'
$script:MaxTokenChars = 32768
$script:MaxBodyChars = 65536

# ---------------------------------------------------------------- libraries

function Import-PlatformLibraries {
    <# Loads the pinned Microsoft.IdentityModel DLLs, refusing any file whose SHA-256 differs from lib/manifest.json. #>
    [CmdletBinding()]
    param([string]$LibPath = $script:LibRoot)
    $manifest = Get-Content (Join-Path $LibPath 'manifest.json') -Raw | ConvertFrom-Json
    # Check every file before loading any of them.
    foreach ($f in $manifest.files) {
        $path = Join-Path $LibPath $f.file
        if (-not (Test-Path $path)) { throw "Library missing: $($f.file). Run lib/Fetch-Libs.ps1." }
        $hash = (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -ne $f.sha256) { throw "Library $($f.file) does not match its pinned SHA-256. Refusing to load it." }
    }
    foreach ($f in $manifest.files) {
        $name = [IO.Path]::GetFileNameWithoutExtension($f.file)
        $path = Join-Path $LibPath $f.file
        $loaded = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq $name }
        if ($loaded) {
            $loadedHash = (Get-FileHash $loaded.Location -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($loadedHash -ne $f.sha256) { throw "A different copy of $name is already loaded. Refusing to continue." }
            continue
        }
        Add-Type -Path $path
    }
}

# ---------------------------------------------------------------- small helpers

function New-RandomToken {
    param([int]$Bytes = 32)
    $b = [byte[]]::new($Bytes)
    [Security.Cryptography.RandomNumberGenerator]::Fill($b)
    [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-TextHash {
    param([string]$Text)
    $h = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text))
    [Convert]::ToHexString($h)
}

function Test-FixedTimeEqual {
    param([string]$A, [string]$B)
    if ($null -eq $A -or $null -eq $B) { return $false }
    [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
        [Text.Encoding]::UTF8.GetBytes($A), [Text.Encoding]::UTF8.GetBytes($B))
}

function Get-PlatformNow { param($Platform) & $Platform.Clock }

function ConvertTo-SafeText {
    param([string]$Text, [int]$Max = 200)
    if (-not $Text) { return '' }
    $t = ($Text -replace '[\p{C}]', '').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) }
    $t
}

# ---------------------------------------------------------------- configuration and platform object

function New-Platform {
    <#
    .SYNOPSIS
      Creates the platform object for one module. -Config holds public values only (tenant, client, redirect URI,
      module path, role prefix). -Audit is the product's callback, called with one hashtable per event.
      -Fetch (optional) is a scriptblock taking a URI and returning the JSON text; tests pass a fake.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][scriptblock]$Audit,
        [scriptblock]$Fetch,
        [scriptblock]$Clock = { [datetime]::UtcNow }
    )
    Import-PlatformLibraries
    $guid = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
    $c = @{
        AuthorityHost            = 'login.microsoftonline.com'
        PostLogoutRedirectUri    = $null
        SessionMaxHours          = 8
        SessionIdleMinutes       = 30
        FreshSignInMinutes       = 15
        PreSignInMinutes         = 10
        ClockSkewMinutes         = 5
        KeyRefreshMinSeconds     = 300
        KeyCacheHours            = 24
        CustomHeaderName         = 'X-Argus-Request'
        # UNVERIFIED against Microsoft Learn (see docs/design/signin.md, "Open item"): the request parameters that
        # force a fresh sign-in. Kept in one place so it can be changed once the source is checked.
        FreshSignInParameters    = [ordered]@{ prompt = 'login' }
    }
    foreach ($k in $Config.Keys) { $c[$k] = $Config[$k] }
    foreach ($req in 'TenantId', 'ClientId', 'RedirectUri', 'ModulePath', 'RolePrefix') {
        if (-not $c.ContainsKey($req) -or -not $c[$req]) { throw "Sign-in config is missing '$req'." }
    }
    if ($c.TenantId -notmatch $guid) { throw 'TenantId must be a GUID (single tenant only).' }
    if ($c.ClientId -notmatch $guid) { throw 'ClientId must be a GUID.' }
    if ($c.ModulePath -notmatch '^/[a-z0-9-]+$') { throw "ModulePath must look like '/assure'." }
    if ($c.RolePrefix -notmatch '^[A-Za-z]+\.$') { throw "RolePrefix must look like 'Assure.'." }
    $uri = [Uri]$c.RedirectUri
    if (-not ($uri.Scheme -eq 'https' -or ($uri.Scheme -eq 'http' -and $uri.Host -eq 'localhost'))) {
        throw 'RedirectUri must be https, or http://localhost for testing.'
    }
    if ($uri.AbsolutePath -ne "$($c.ModulePath)/auth/callback") { throw "RedirectUri path must be $($c.ModulePath)/auth/callback." }
    foreach ($forbidden in 'ClientSecret', 'Secret', 'Password', 'Certificate') {
        if ($c.ContainsKey($forbidden)) { throw "Config must not contain '$forbidden': sign-in uses no secret." }
    }
    $c.Issuer = "https://$($c.AuthorityHost)/$($c.TenantId)/v2.0"
    $c.MetadataUri = "$($c.Issuer)/.well-known/openid-configuration"
    $c.AuthorizeUri = "https://$($c.AuthorityHost)/$($c.TenantId)/oauth2/v2.0/authorize"
    $c.LogoutUri = "https://$($c.AuthorityHost)/$($c.TenantId)/oauth2/v2.0/logout"

    if (-not $Fetch) {
        $Fetch = {
            param($Uri)
            if ($Uri -notmatch '^https://') { throw 'Refusing a non-HTTPS metadata fetch.' }
            (Invoke-WebRequest -Uri $Uri -TimeoutSec 10 -MaximumRedirection 0).Content
        }
    }
    @{
        Config   = $c
        Audit    = $Audit
        Fetch    = $Fetch
        Clock    = $Clock
        Handler  = [Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler]::new()
        Pre      = @{}   # sha256(pre-sign-in cookie) -> state, nonce, created, fresh-for-session
        Sessions = @{}   # sha256(session cookie)     -> the session
        Keys     = @{ Set = $null; FetchedAt = $null; LastAttempt = $null; LastError = $null }
    }
}

function Write-PlatformAudit {
    param($Platform, [string]$Event, $Request, [string]$Oid = '', [string]$Name = '', [string]$Reason = '', [hashtable]$Extra)
    $rec = [ordered]@{
        Time          = (Get-PlatformNow $Platform).ToString('o')
        Event         = $Event
        Oid           = $Oid
        Name          = $Name
        ClientAddress = (Get-PlatformClientAddress $Request)
        Reason        = $Reason
    }
    if ($Extra) { foreach ($k in $Extra.Keys) { $rec[$k] = $Extra[$k] } }
    & $Platform.Audit ([hashtable]$rec)
}

function Get-PlatformClientAddress {
    <# Audit log only. Takes the rightmost X-Forwarded-For entry (the one our own proxy added), else the socket address. #>
    param($Request)
    if (-not $Request) { return '' }
    $xff = $Request.Headers['X-Forwarded-For']
    if ($xff) {
        $last = ($xff -split ',')[-1].Trim()
        $ip = $null
        if ([Net.IPAddress]::TryParse($last, [ref]$ip)) { return $ip.ToString() }
    }
    [string]$Request.RemoteAddress
}

# ---------------------------------------------------------------- signing keys

function Update-PlatformKeys {
    <# Fetches the metadata document and key set. Rate limited: returns $false if asked again too soon. #>
    param($Platform)
    $c = $Platform.Config
    $now = Get-PlatformNow $Platform
    $k = $Platform.Keys
    if ($k.LastAttempt -and ($now - $k.LastAttempt).TotalSeconds -lt $c.KeyRefreshMinSeconds) { return $false }
    $k.LastAttempt = $now
    try {
        $meta = [Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration]::new((& $Platform.Fetch $c.MetadataUri))
        if ($meta.Issuer -ne $c.Issuer) { return $false }
        if ($meta.JwksUri -notmatch '^https://') { return $false }
        $set = [Microsoft.IdentityModel.Tokens.JsonWebKeySet]::new((& $Platform.Fetch $meta.JwksUri))
        if ($set.Keys.Count -eq 0) { return $false }
        $k.Set = $set
        $k.FetchedAt = $now
        return $true
    } catch { $k.LastError = $_.Exception.Message; return $false }
}

function Find-PlatformSigningKey {
    param($Platform, [string]$Kid)
    $k = $Platform.Keys
    $now = Get-PlatformNow $Platform
    if (-not $k.Set -or ($now - $k.FetchedAt).TotalHours -gt $Platform.Config.KeyCacheHours) { [void](Update-PlatformKeys $Platform) }
    $key = if ($k.Set) { $k.Set.Keys | Where-Object { $_.Kid -eq $Kid } | Select-Object -First 1 }
    if (-not $key) {
        # Unknown kid: Microsoft rotates keys, so refresh once (limited by KeyRefreshMinSeconds), then look again.
        if (Update-PlatformKeys $Platform) { $key = $k.Set.Keys | Where-Object { $_.Kid -eq $Kid } | Select-Object -First 1 }
    }
    $key
}

# ---------------------------------------------------------------- ID token validation

function Test-PlatformIdToken {
    <# Returns @{ Ok; Reason; Claims }. Reason is a short code, never any part of the token. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Platform, [Parameter(Mandatory)][string]$IdToken, [Parameter(Mandatory)][string]$ExpectedNonce)
    $c = $Platform.Config
    $fail = { param($r) @{ Ok = $false; Reason = $r; Claims = $null } }
    if ($IdToken.Length -gt $script:MaxTokenChars) { return & $fail 'token_too_large' }
    try { $jwt = [Microsoft.IdentityModel.JsonWebTokens.JsonWebToken]::new($IdToken) } catch { return & $fail 'malformed_token' }
    # Header is read only to choose the key; nothing in it is trusted.
    if ($jwt.Alg -ne 'RS256') { return & $fail 'alg_not_allowed' }
    if (-not $jwt.Kid) { return & $fail 'missing_kid' }
    $key = Find-PlatformSigningKey $Platform $jwt.Kid
    if (-not $key) { return & $fail $(if ($Platform.Keys.Set) { 'unknown_kid' } else { 'keys_unavailable' }) }

    $p = [Microsoft.IdentityModel.Tokens.TokenValidationParameters]::new()
    $p.ValidateIssuer = $true;            $p.ValidIssuer = $c.Issuer
    $p.ValidateAudience = $true;          $p.ValidAudience = $c.ClientId
    $p.ValidateLifetime = $true;          $p.RequireExpirationTime = $true
    $p.ClockSkew = [TimeSpan]::FromMinutes($c.ClockSkewMinutes)
    $p.RequireSignedTokens = $true;       $p.ValidateIssuerSigningKey = $true
    $p.IssuerSigningKeys = [Microsoft.IdentityModel.Tokens.SecurityKey[]]@($key)
    $p.ValidAlgorithms = [string[]]@('RS256')
    $res = $Platform.Handler.ValidateTokenAsync($IdToken, $p).GetAwaiter().GetResult()
    if (-not $res.IsValid) {
        $reason = switch ($res.Exception.GetType().Name) {
            'SecurityTokenExpiredException'              { 'token_expired' }
            'SecurityTokenNoExpirationException'         { 'missing_exp' }
            'SecurityTokenNotYetValidException'          { 'token_not_yet_valid' }
            'SecurityTokenInvalidSignatureException'     { 'bad_signature' }
            'SecurityTokenSignatureKeyNotFoundException' { 'unknown_kid' }
            'SecurityTokenInvalidIssuerException'        { 'bad_issuer' }
            'SecurityTokenInvalidAudienceException'      { 'bad_audience' }
            'SecurityTokenInvalidAlgorithmException'     { 'alg_not_allowed' }
            default                                      { 'invalid_token' }
        }
        return & $fail $reason
    }
    $claims = $res.Claims
    if (-not $claims.ContainsKey('nbf')) { return & $fail 'missing_nbf' }
    if (-not $claims.ContainsKey('tid') -or "$($claims['tid'])" -ne $c.TenantId) { return & $fail 'bad_tenant' }
    if (-not $claims.ContainsKey('nonce') -or -not (Test-FixedTimeEqual "$($claims['nonce'])" $ExpectedNonce)) { return & $fail 'bad_nonce' }
    if (-not $claims.ContainsKey('oid') -or "$($claims['oid'])" -notmatch '^[0-9a-fA-F-]{36}$') { return & $fail 'missing_oid' }
    @{ Ok = $true; Reason = ''; Claims = $claims }
}

function Get-PlatformRolesFromClaims {
    <# Only the token's roles claim, only this module's prefix. No claim means no roles. #>
    param($Claims, [string]$Prefix)
    if (-not $Claims.ContainsKey('roles')) { return @() }
    $raw = $Claims['roles']
    $all = if ($raw -is [string]) { @($raw) } else { @($raw | ForEach-Object { "$_" }) }
    @($all | Where-Object { $_.StartsWith($Prefix, [StringComparison]::Ordinal) -and $_.Length -gt $Prefix.Length } | Sort-Object -Unique)
}

# ---------------------------------------------------------------- sessions

function New-PlatformSession {
    param($Platform, $Request, [string]$Oid, [string]$Name, [string[]]$Roles, $Created, $FreshAt)
    $now = Get-PlatformNow $Platform
    if ($Platform.Sessions.Count -gt 10000) { Clear-PlatformExpired $Platform }
    $id = New-RandomToken
    $Platform.Sessions[(Get-TextHash $id)] = @{
        Oid = $Oid; Name = $Name; Roles = @($Roles)
        Created = $(if ($Created) { $Created } else { $now })
        LastSeen = $now; FreshAt = $FreshAt
        Csrf = (New-RandomToken)
    }
    $id
}

function Clear-PlatformExpired {
    param($Platform)
    $now = Get-PlatformNow $Platform; $c = $Platform.Config
    foreach ($h in @($Platform.Sessions.Keys)) {
        $s = $Platform.Sessions[$h]
        if (($now - $s.Created).TotalHours -ge $c.SessionMaxHours -or ($now - $s.LastSeen).TotalMinutes -ge $c.SessionIdleMinutes) { $Platform.Sessions.Remove($h) }
    }
    foreach ($h in @($Platform.Pre.Keys)) {
        if (($now - $Platform.Pre[$h].Created).TotalMinutes -ge $c.PreSignInMinutes) { $Platform.Pre.Remove($h) }
    }
}

function Get-PlatformSession {
    <# Looks up the session for a cookie value. Ends it (and says why) when past 8 hours or idle for 30 minutes. #>
    param($Platform, [string]$CookieValue, $Request)
    if (-not $CookieValue) { return $null }
    $h = Get-TextHash $CookieValue
    $s = $Platform.Sessions[$h]
    if (-not $s) { return $null }
    $now = Get-PlatformNow $Platform; $c = $Platform.Config
    $why = if (($now - $s.Created).TotalHours -ge $c.SessionMaxHours) { 'absolute' }
           elseif (($now - $s.LastSeen).TotalMinutes -ge $c.SessionIdleMinutes) { 'idle' }
    if ($why) {
        $Platform.Sessions.Remove($h)
        Write-PlatformAudit $Platform 'SessionExpired' $Request $s.Oid $s.Name $why
        return $null
    }
    $s.LastSeen = $now
    $s
}

function Test-PlatformFreshSignIn {
    <# True if the person signed in again (a forced fresh sign-in) within the last FreshSignInMinutes. #>
    param([Parameter(Mandatory)]$Platform, [Parameter(Mandatory)]$Session)
    if (-not $Session.FreshAt) { return $false }
    ((Get-PlatformNow $Platform) - $Session.FreshAt).TotalMinutes -lt $Platform.Config.FreshSignInMinutes
}

function Test-PlatformRole {
    <# -Role may be the short name ('Editor') or the full name ('Assure.Editor'). #>
    param([Parameter(Mandatory)]$Platform, [Parameter(Mandatory)]$Session, [Parameter(Mandatory)][string]$Role)
    $full = if ($Role.StartsWith($Platform.Config.RolePrefix, [StringComparison]::Ordinal)) { $Role } else { $Platform.Config.RolePrefix + $Role }
    $Session.Roles -ccontains $full
}

# ---------------------------------------------------------------- responses and cookies

function New-PlatformResponse {
    param([int]$Status = 200, [string]$Body = '', [string]$ContentType = 'text/plain; charset=utf-8', [string]$Location, [string[]]$SetCookies = @())
    $h = [ordered]@{ 'Cache-Control' = 'no-store'; 'X-Content-Type-Options' = 'nosniff' }
    if ($Location) { $h['Location'] = $Location }
    @{ Status = $Status; Headers = $h; SetCookies = $SetCookies; Body = $Body; ContentType = $ContentType }
}

function New-CookieHeader {
    param([string]$Name, [string]$Value, [string]$Path, [string]$SameSite, [int]$MaxAgeSeconds)
    "$Name=$Value; Path=$Path; Max-Age=$MaxAgeSeconds; Secure; HttpOnly; SameSite=$SameSite"
}

function ConvertFrom-FormBody {
    <# Returns a hashtable, or $null if the body is not a plain form with unique keys. #>
    param([string]$Body)
    $out = @{}
    if (-not $Body) { return $out }
    foreach ($pair in $Body -split '&') {
        if (-not $pair) { continue }
        $kv = $pair -split '=', 2
        try {
            $k = [Uri]::UnescapeDataString($kv[0].Replace('+', ' '))
            $v = if ($kv.Count -gt 1) { [Uri]::UnescapeDataString($kv[1].Replace('+', ' ')) } else { '' }
        } catch { return $null }
        if ($out.ContainsKey($k)) { return $null }
        $out[$k] = $v
    }
    $out
}

# ---------------------------------------------------------------- the sign-in routes

function Start-PlatformSignIn {
    param($Platform, $Request, [switch]$Fresh, $ExistingSessionCookie)
    $c = $Platform.Config
    $now = Get-PlatformNow $Platform
    if ($Platform.Pre.Count -gt 2000) { Clear-PlatformExpired $Platform }
    if ($Platform.Pre.Count -gt 2000) { return New-PlatformResponse 429 'Too many sign-ins in progress.' }
    $id = New-RandomToken; $state = New-RandomToken; $nonce = New-RandomToken
    $Platform.Pre[(Get-TextHash $id)] = @{
        State = $state; Nonce = $nonce; Created = $now
        FreshForSession = $(if ($Fresh) { Get-TextHash $ExistingSessionCookie })
    }
    $q = [ordered]@{
        client_id = $c.ClientId; response_type = 'id_token'; response_mode = 'form_post'
        redirect_uri = $c.RedirectUri; scope = 'openid profile'; state = $state; nonce = $nonce
    }
    if ($Fresh) { foreach ($k in $c.FreshSignInParameters.Keys) { $q[$k] = $c.FreshSignInParameters[$k] } }
    $qs = ($q.GetEnumerator() | ForEach-Object { "$($_.Key)=$([Uri]::EscapeDataString([string]$_.Value))" }) -join '&'
    $cookie = New-CookieHeader $script:PreCookie $id "$($c.ModulePath)/auth" 'None' ($c.PreSignInMinutes * 60)
    New-PlatformResponse 302 -Location "$($c.AuthorizeUri)?$qs" -SetCookies @($cookie)
}

function Invoke-PlatformCallback {
    param($Platform, $Request)
    $c = $Platform.Config
    $refuse = {
        param($reason, $oid = '', $name = '')
        Write-PlatformAudit $Platform 'TokenRefused' $Request $oid $name $reason
        $clear = New-CookieHeader $script:PreCookie '' "$($c.ModulePath)/auth" 'None' 0
        New-PlatformResponse 400 'Sign-in was refused.' -SetCookies @($clear)
    }
    if ($Request.Method -ne 'POST') { return New-PlatformResponse 405 'POST only.' }
    if (($Request.Headers['Content-Type'] -split ';')[0].Trim() -ne 'application/x-www-form-urlencoded') { return & $refuse 'bad_content_type' }
    if ($Request.Body.Length -gt $script:MaxBodyChars) { return & $refuse 'body_too_large' }
    $form = ConvertFrom-FormBody $Request.Body
    if ($null -eq $form) { return & $refuse 'malformed_form' }
    # The pre-sign-in record is single use: taken out now, whatever happens next.
    $preCookie = $Request.Cookies[$script:PreCookie]
    $pre = $null
    if ($preCookie) { $h = Get-TextHash $preCookie; $pre = $Platform.Pre[$h]; $Platform.Pre.Remove($h) }
    if ($form.ContainsKey('error')) {
        $code = if ($form['error'] -match '^[a-z_]{1,64}$') { $form['error'] } else { 'unknown' }
        return & $refuse "entra_error:$code"
    }
    foreach ($k in $form.Keys) { if ($k -notin 'id_token', 'state') { return & $refuse 'unexpected_form_field' } }
    if (-not $form.ContainsKey('id_token') -or -not $form.ContainsKey('state')) { return & $refuse 'missing_form_field' }
    if (-not $pre) { return & $refuse 'no_pre_signin_cookie' }
    if (((Get-PlatformNow $Platform) - $pre.Created).TotalMinutes -ge $c.PreSignInMinutes) { return & $refuse 'pre_signin_expired' }
    if (-not (Test-FixedTimeEqual $form['state'] $pre.State)) { return & $refuse 'state_mismatch' }

    $v = Test-PlatformIdToken $Platform $form['id_token'] $pre.Nonce
    if (-not $v.Ok) { return & $refuse $v.Reason }
    $oid = "$($v.Claims['oid'])"
    $name = ConvertTo-SafeText $(if ($v.Claims.ContainsKey('name')) { "$($v.Claims['name'])" } elseif ($v.Claims.ContainsKey('preferred_username')) { "$($v.Claims['preferred_username'])" } else { $oid })
    $roles = Get-PlatformRolesFromClaims $v.Claims $c.RolePrefix

    $created = $null; $freshAt = $null; $event = 'SignIn'
    if ($pre.FreshForSession) {
        # A forced fresh sign-in: same person, new roles read, same absolute 8-hour limit.
        $old = $Platform.Sessions[$pre.FreshForSession]
        if (-not $old) { return & $refuse 'fresh_signin_no_session' $oid $name }
        if ($old.Oid -ne $oid) { return & $refuse 'fresh_signin_other_person' $oid $name }
        $created = $old.Created; $freshAt = Get-PlatformNow $Platform; $event = 'FreshSignIn'
        if ((($old.Roles | Sort-Object) -join ',') -ne (($roles | Sort-Object) -join ',')) {
            Write-PlatformAudit $Platform 'RoleChange' $Request $oid $name '' @{ Before = ($old.Roles -join ','); After = ($roles -join ',') }
        }
        $Platform.Sessions.Remove($pre.FreshForSession)
    }
    Write-PlatformAudit $Platform $event $Request $oid $name '' @{ Roles = ($roles -join ',') }
    $sid = New-PlatformSession $Platform $Request $oid $name $roles $created $freshAt
    $sess = New-CookieHeader $script:SessionCookie $sid $c.ModulePath 'Lax' ($c.SessionMaxHours * 3600)
    $clear = New-CookieHeader $script:PreCookie '' "$($c.ModulePath)/auth" 'None' 0
    New-PlatformResponse 302 -Location "$($c.ModulePath)/" -SetCookies @($sess, $clear)
}

function Invoke-PlatformSignOut {
    param($Platform, $Request, $Session, [string]$SessionCookie)
    $c = $Platform.Config
    Write-PlatformAudit $Platform 'SignOut' $Request $Session.Oid $Session.Name
    $Platform.Sessions.Remove((Get-TextHash $SessionCookie))
    $target = $c.LogoutUri
    if ($c.PostLogoutRedirectUri) { $target += '?post_logout_redirect_uri=' + [Uri]::EscapeDataString($c.PostLogoutRedirectUri) }
    $clear = New-CookieHeader $script:SessionCookie '' $c.ModulePath 'Lax' 0
    New-PlatformResponse 303 -Location $target -SetCookies @($clear)
}

# ---------------------------------------------------------------- the front door

function Invoke-PlatformRequest {
    <#
    .SYNOPSIS
      Handles one request. Sign-in routes are answered here; everything else needs a session, and for
      state-changing methods the custom header and the anti-forgery token, then goes to -Next.
      -Next receives a context: Session (Oid, Name, Roles, Csrf, FreshAt), Request, Platform. Identity comes only
      from the session; no identity, role or user header is ever read.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Platform, [Parameter(Mandatory)]$Request, [Parameter(Mandatory)][scriptblock]$Next)
    try {
        $c = $Platform.Config
        $path = $Request.Path
        if ($path -ne $c.ModulePath -and -not $path.StartsWith("$($c.ModulePath)/")) { return New-PlatformResponse 404 'Not found.' }
        $rel = $path.Substring($c.ModulePath.Length)
        $cookie = $Request.Cookies[$script:SessionCookie]
        switch ($rel) {
            '/auth/signin'   { if ($Request.Method -ne 'GET') { return New-PlatformResponse 405 'GET only.' }; return Start-PlatformSignIn $Platform $Request }
            '/auth/callback' { return Invoke-PlatformCallback $Platform $Request }
            '/auth/fresh' {
                if ($Request.Method -ne 'GET') { return New-PlatformResponse 405 'GET only.' }
                if (-not (Get-PlatformSession $Platform $cookie $Request)) { return Start-PlatformSignIn $Platform $Request }
                return Start-PlatformSignIn $Platform $Request -Fresh -ExistingSessionCookie $cookie
            }
        }
        $session = Get-PlatformSession $Platform $cookie $Request
        if (-not $session) {
            if ($Request.Method -eq 'GET') { return New-PlatformResponse 302 -Location "$($c.ModulePath)/auth/signin" }
            return New-PlatformResponse 401 'Sign in first.'
        }
        if ($Request.Method -notin 'GET', 'HEAD', 'OPTIONS') {
            if (-not $Request.Headers[$c.CustomHeaderName]) { return New-PlatformResponse 403 'Missing request header.' }
            $sent = $Request.Headers['X-Argus-CSRF']
            if (-not $sent -and $Request.Form) { $sent = $Request.Form['csrf'] }
            if (-not (Test-FixedTimeEqual "$sent" $session.Csrf)) { return New-PlatformResponse 403 'Missing or wrong anti-forgery token.' }
        }
        if ($rel -eq '/auth/signout') {
            if ($Request.Method -ne 'POST') { return New-PlatformResponse 405 'POST only.' }
            return Invoke-PlatformSignOut $Platform $Request $session $cookie
        }
        & $Next @{ Session = $session; Request = $Request; Platform = $Platform }
    } catch {
        # Fail closed. The reason goes to the product's audit if it can take it, never to the browser.
        try { Write-PlatformAudit $Platform 'PlatformError' $Request '' '' $_.Exception.GetType().Name } catch { }
        New-PlatformResponse 503 'Sign-in is unavailable.'
    }
}

# ---------------------------------------------------------------- the listener (thin; the logic is above)

function Assert-PlatformLoopbackPrefixes {
    param([string[]]$Prefixes)
    if (-not $Prefixes) { throw 'No listener prefix given.' }
    foreach ($p in $Prefixes) {
        if ($p -notmatch '^http://127\.0\.0\.1:\d{1,5}/') { throw "Server mode binds to 127.0.0.1 only. Refusing '$p'." }
    }
}

function ConvertFrom-ListenerContext {
    param($Context)
    $r = $Context.Request
    $headers = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $r.Headers.AllKeys) { $headers[$k] = $r.Headers[$k] }
    $cookies = @{}
    if ($headers.ContainsKey('Cookie')) {
        foreach ($part in $headers['Cookie'] -split ';') {
            $kv = $part.Trim() -split '=', 2
            if ($kv.Count -eq 2 -and -not $cookies.ContainsKey($kv[0])) { $cookies[$kv[0]] = $kv[1] }
        }
    }
    $body = ''
    if ($r.HasEntityBody -and $r.ContentLength64 -le $script:MaxBodyChars) {
        $sr = [IO.StreamReader]::new($r.InputStream, [Text.Encoding]::UTF8)
        try { $body = $sr.ReadToEnd() } finally { $sr.Dispose() }
    } elseif ($r.HasEntityBody) { $body = 'x' * ($script:MaxBodyChars + 1) }
    $form = $null
    if ($body -and ($headers['Content-Type'] -split ';')[0].Trim() -eq 'application/x-www-form-urlencoded') { $form = ConvertFrom-FormBody $body }
    [pscustomobject]@{
        Method = $r.HttpMethod; Path = $r.Url.AbsolutePath; Headers = $headers; Cookies = $cookies
        Body = $body; Form = $form; RemoteAddress = $(if ($r.RemoteEndPoint) { $r.RemoteEndPoint.Address.ToString() } else { '' })
    }
}

function Start-PlatformServer {
    <# Binds to 127.0.0.1 only and serves until $Stop.Stop is true. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Platform, [Parameter(Mandatory)][string[]]$Prefixes, [Parameter(Mandatory)][scriptblock]$Next, [hashtable]$Stop = @{ Stop = $false })
    Assert-PlatformLoopbackPrefixes $Prefixes
    $l = [Net.HttpListener]::new()
    foreach ($p in $Prefixes) { $l.Prefixes.Add($p) }
    $l.Start()
    try {
        while (-not $Stop.Stop -and $l.IsListening) {
            $task = $l.GetContextAsync()
            while (-not $task.Wait(200)) { if ($Stop.Stop) { return } }
            $ctx = $task.Result
            # One bad request must never stop the server: anything unexpected becomes a plain 400.
            try {
                $resp = Invoke-PlatformRequest -Platform $Platform -Request (ConvertFrom-ListenerContext $ctx) -Next $Next
            } catch { $resp = New-PlatformResponse 400 'Bad request.' }
            try {
                $ctx.Response.StatusCode = $resp.Status
                $ctx.Response.ContentType = $resp.ContentType
                foreach ($k in $resp.Headers.Keys) { $ctx.Response.Headers[$k] = $resp.Headers[$k] }
                foreach ($sc in $resp.SetCookies) { $ctx.Response.Headers.Add('Set-Cookie', $sc) }
                $bytes = [Text.Encoding]::UTF8.GetBytes($resp.Body)
                $ctx.Response.ContentLength64 = $bytes.Length
                $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            } catch { } finally { try { $ctx.Response.Close() } catch { } }
        }
    } finally { $l.Stop(); $l.Close() }
}

Export-ModuleMember -Function Import-PlatformLibraries, New-Platform, Test-PlatformIdToken, Invoke-PlatformRequest,
    Test-PlatformFreshSignIn, Test-PlatformRole, Start-PlatformServer, Assert-PlatformLoopbackPrefixes,
    Get-PlatformRolesFromClaims, New-PlatformResponse, ConvertFrom-FormBody
