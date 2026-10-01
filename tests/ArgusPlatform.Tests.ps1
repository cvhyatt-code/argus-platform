#requires -Modules Pester
BeforeAll {
    . $PSScriptRoot/TestHelpers.ps1
    Import-Module (Join-Path $PSScriptRoot '../src/ArgusPlatform.psm1') -Force

    function New-Env {
        $e = @{}
        $e.Key = New-TestKey 'key-1'
        $e.Pub = @{ Keys = @($e.Key); MetaTenant = $script:Tenant; Calls = @() }
        $e.Now = @{ T = [datetime]::UtcNow }
        $e.Audit = [System.Collections.Generic.List[hashtable]]::new()
        $audit = $e.Audit; $now = $e.Now
        $e.P = New-Platform -Config @{
            TenantId = $script:Tenant; ClientId = $script:Client; ModulePath = '/assure'; RolePrefix = 'Assure.'
            RedirectUri = 'https://argus.example.test/assure/auth/callback'
        } -Audit { param($r) $audit.Add($r) }.GetNewClosure() -Fetch (New-TestFetcher $e.Pub) -Clock { $now.T }.GetNewClosure()
        $e
    }
    function Start-Flow($e) {
        $r = Invoke-PlatformRequest -Platform $e.P -Request (New-TestRequest -Path '/assure/auth/signin') -Next { }
        @{ Resp = $r; Pre = (Get-CookieValue $r 'argus_pre'); State = (Get-QueryValue $r.Headers.Location 'state'); Nonce = (Get-QueryValue $r.Headers.Location 'nonce') }
    }
    function Send-Callback($e, $flow, [string]$Token, [string]$State, [string]$Extra = '') {
        if (-not $State) { $State = $flow.State }
        $body = "id_token=$([Uri]::EscapeDataString($Token))&state=$([Uri]::EscapeDataString($State))$Extra"
        $cookies = @{}; if ($flow.Pre) { $cookies['argus_pre'] = $flow.Pre }
        Invoke-PlatformRequest -Platform $e.P -Next { } -Request (New-TestRequest -Method POST -Path '/assure/auth/callback' -Cookies $cookies -Body $body)
    }
    function Sign-In($e, [hashtable]$Claims = @{}) {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce -Claims $Claims
        $r = Send-Callback $e $f $t
        @{ Resp = $r; Session = (Get-CookieValue $r 'argus_session') }
    }
    function Get-Page($e, $Session, [string]$Method = 'GET', [hashtable]$Headers = @{}, [string]$Body = '', [string]$Path = '/assure/page') {
        Invoke-PlatformRequest -Platform $e.P -Request (New-TestRequest -Method $Method -Path $Path -Headers $Headers -Cookies @{ argus_session = $Session } -Body $Body) -Next {
            param($ctx) New-PlatformResponse 200 ("who=$($ctx.Session.Oid);name=$($ctx.Session.Name);roles=$($ctx.Session.Roles -join ',');csrf=$($ctx.Session.Csrf)")
        }
    }
    function Get-Refusals($e) { @($e.Audit | Where-Object Event -eq 'TokenRefused') }
}

Describe 'Libraries' {
    It 'refuses a changed library file' {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("lib-" + [guid]::NewGuid())
        Copy-Item (Join-Path $PSScriptRoot '../lib') $tmp -Recurse
        Add-Content (Join-Path $tmp 'Microsoft.IdentityModel.Tokens.dll') ([byte[]]@(120)) -AsByteStream
        { Import-PlatformLibraries -LibPath $tmp } | Should -Throw '*pinned SHA-256*'
        Remove-Item $tmp -Recurse -Force
    }
    It 'refuses a missing library file' {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("lib-" + [guid]::NewGuid())
        Copy-Item (Join-Path $PSScriptRoot '../lib') $tmp -Recurse
        Remove-Item (Join-Path $tmp 'Microsoft.IdentityModel.Logging.dll')
        { Import-PlatformLibraries -LibPath $tmp } | Should -Throw '*missing*'
        Remove-Item $tmp -Recurse -Force
    }
}

Describe 'Configuration' {
    It 'refuses a config that holds a secret' {
        { New-Platform -Audit { } -Config @{ TenantId = $script:Tenant; ClientId = $script:Client; ModulePath = '/assure'; RolePrefix = 'Assure.'
            RedirectUri = 'https://a.test/assure/auth/callback'; ClientSecret = 'x' } } | Should -Throw '*no secret*'
    }
    It 'refuses a plain-http redirect URI that is not localhost' {
        { New-Platform -Audit { } -Config @{ TenantId = $script:Tenant; ClientId = $script:Client; ModulePath = '/assure'; RolePrefix = 'Assure.'
            RedirectUri = 'http://a.test/assure/auth/callback' } } | Should -Throw '*https*'
    }
    It 'refuses a tenant that is not a GUID (single tenant only)' {
        { New-Platform -Audit { } -Config @{ TenantId = 'common'; ClientId = $script:Client; ModulePath = '/assure'; RolePrefix = 'Assure.'
            RedirectUri = 'https://a.test/assure/auth/callback' } } | Should -Throw '*GUID*'
    }
}

Describe 'Binding' {
    It 'accepts 127.0.0.1' { { Assert-PlatformLoopbackPrefixes @('http://127.0.0.1:8443/') } | Should -Not -Throw }
    It 'refuses <p>' -ForEach @(@{ p = 'http://+:8443/' }, @{ p = 'http://*:8443/' }, @{ p = 'http://0.0.0.0:8443/' }, @{ p = 'http://localhost:8443/' }, @{ p = 'http://10.1.2.3:8443/' }) {
        { Assert-PlatformLoopbackPrefixes @($p) } | Should -Throw '*127.0.0.1 only*'
    }
}

Describe 'Sign-in request' {
    BeforeEach { $e = New-Env }
    It 'sends the right authorize request and sets the pre-sign-in cookie' {
        $f = Start-Flow $e
        $loc = $f.Resp.Headers.Location
        $loc | Should -BeLike "https://login.microsoftonline.com/$script:Tenant/oauth2/v2.0/authorize?*"
        Get-QueryValue $loc 'response_type' | Should -Be 'id_token'
        Get-QueryValue $loc 'response_mode' | Should -Be 'form_post'
        Get-QueryValue $loc 'scope' | Should -Be 'openid profile'
        Get-QueryValue $loc 'client_id' | Should -Be $script:Client
        $f.State.Length | Should -BeGreaterThan 20
        $f.Nonce.Length | Should -BeGreaterThan 20
        $f.State | Should -Not -Be $f.Nonce
        $cookie = $f.Resp.SetCookies[0]
        $cookie | Should -BeLike 'argus_pre=*'
        $cookie | Should -Match 'SameSite=None'; $cookie | Should -Match 'Secure'; $cookie | Should -Match 'HttpOnly'; $cookie | Should -Match 'Max-Age=600'
        $loc | Should -Not -Match 'prompt='
    }
    It 'uses a new state and nonce every time' {
        (Start-Flow $e).State | Should -Not -Be (Start-Flow $e).State
    }
}

Describe 'ID token validation' {
    BeforeEach { $e = New-Env }

    It 'accepts a good token, makes a session, and audits the sign-in' {
        $s = Sign-In $e
        $s.Resp.Status | Should -Be 302
        $s.Resp.Headers.Location | Should -Be '/assure/'
        $s.Session | Should -Not -BeNullOrEmpty
        $cookie = $s.Resp.SetCookies | Where-Object { $_ -like 'argus_session=*' }
        $cookie | Should -Match 'Secure'; $cookie | Should -Match 'HttpOnly'; $cookie | Should -Match 'SameSite=Lax'; $cookie | Should -Match 'Path=/assure(;|$)'
        $page = Get-Page $e $s.Session
        $page.Body | Should -BeLike "who=$script:Oid;name=Test Person;roles=Assure.Editor;*"
        $in = $e.Audit | Where-Object Event -eq 'SignIn'
        $in.Oid | Should -Be $script:Oid; $in.Name | Should -Be 'Test Person'; $in.ClientAddress | Should -Be '127.0.0.1'
    }
    It 'refuses a bad signature' {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce -Tamper
        (Send-Callback $e $f $t).Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'bad_signature'
    }
    It 'refuses a token signed by a different key with the same kid' {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key (New-TestKey 'key-1') -Nonce $f.Nonce
        (Send-Callback $e $f $t).Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'bad_signature'
    }
    It 'refuses the wrong issuer' {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce -Claims @{ iss = 'https://login.microsoftonline.com/99999999-9999-9999-9999-999999999999/v2.0' }
        (Send-Callback $e $f $t).Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'bad_issuer'
    }
    It 'refuses the wrong tenant (tid) even with the right issuer' {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce -Claims @{ tid = '99999999-9999-9999-9999-999999999999' }
        (Send-Callback $e $f $t).Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'bad_tenant'
    }
    It 'refuses the wrong audience' {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce -Claims @{ aud = '99999999-9999-9999-9999-999999999999' }
        (Send-Callback $e $f $t).Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'bad_audience'
    }
    It 'refuses an expired token' {
        $f = Start-Flow $e
        $past = [DateTimeOffset]::UtcNow.AddMinutes(-10).ToUnixTimeSeconds()
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce -Claims @{ exp = $past; nbf = ($past - 3600) }
        (Send-Callback $e $f $t).Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'token_expired'
    }
    It 'allows up to 5 minutes of clock skew on exp' {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce -Claims @{ exp = [DateTimeOffset]::UtcNow.AddMinutes(-4).ToUnixTimeSeconds(); nbf = [DateTimeOffset]::UtcNow.AddMinutes(-60).ToUnixTimeSeconds() }
        (Send-Callback $e $f $t).Status | Should -Be 302
    }
    It 'refuses a token not yet valid' {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce -Claims @{ nbf = [DateTimeOffset]::UtcNow.AddMinutes(10).ToUnixTimeSeconds() }
        (Send-Callback $e $f $t).Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'token_not_yet_valid'
    }
    It 'allows up to 5 minutes of clock skew on nbf' {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce -Claims @{ nbf = [DateTimeOffset]::UtcNow.AddMinutes(4).ToUnixTimeSeconds() }
        (Send-Callback $e $f $t).Status | Should -Be 302
    }
    It 'refuses a token with no nbf' {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce -Claims @{ nbf = $null }
        (Send-Callback $e $f $t).Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'missing_nbf'
    }
    It 'refuses a token with no exp' {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce -Claims @{ exp = $null }
        (Send-Callback $e $f $t).Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'missing_exp'
    }
    It 'refuses the wrong nonce' {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key -Nonce 'not-the-nonce'
        (Send-Callback $e $f $t).Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'bad_nonce'
    }
    It 'refuses a token with no nonce' {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce -Claims @{ nonce = $null }
        (Send-Callback $e $f $t).Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'bad_nonce'
    }
    It 'refuses a replayed sign-in (nonce and pre-sign-in cookie are single use)' {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce
        (Send-Callback $e $f $t).Status | Should -Be 302
        (Send-Callback $e $f $t).Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'no_pre_signin_cookie'
    }
    It 'refuses a token from one sign-in used in another' {
        $f1 = Start-Flow $e; $f2 = Start-Flow $e
        $t1 = New-TestIdToken -Key $e.Key -Nonce $f1.Nonce
        (Send-Callback $e $f2 $t1).Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'bad_nonce'
    }
    It 'refuses the wrong state' {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce
        (Send-Callback $e $f $t -State 'forged').Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'state_mismatch'
    }
    It 'refuses a callback with no pre-sign-in cookie' {
        $f = Start-Flow $e; $f.Pre = $null
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce
        (Send-Callback $e $f $t).Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'no_pre_signin_cookie'
    }
    It 'refuses a callback after the pre-sign-in window (10 minutes)' {
        $f = Start-Flow $e
        $e.Now.T = $e.Now.T.AddMinutes(11)
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce
        (Send-Callback $e $f $t).Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'pre_signin_expired'
    }
    It 'refuses alg none' {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce -Alg none
        (Send-Callback $e $f $t).Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'alg_not_allowed'
        $e.Audit.Count | Should -Be 1
    }
    It 'refuses HS256' {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce -Alg HS256
        (Send-Callback $e $f $t).Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'alg_not_allowed'
    }
    It 'refuses form fields other than id_token and state' {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce
        (Send-Callback $e $f $t -Extra '&roles=Assure.Admin').Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'unexpected_form_field'
    }
    It 'refuses an Entra error post and records only its code' {
        $f = Start-Flow $e
        $r = Invoke-PlatformRequest -Platform $e.P -Next { } -Request (New-TestRequest -Method POST -Path '/assure/auth/callback' -Cookies @{ argus_pre = $f.Pre } -Body 'error=access_denied&error_description=secret+words&state=x')
        $r.Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'entra_error:access_denied'
    }
    It 'refuses garbage as a token' {
        $f = Start-Flow $e
        (Send-Callback $e $f 'not.a.jwt').Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'malformed_token'
    }
    It 'never writes the token into the audit record' {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce -Tamper
        [void](Send-Callback $e $f $t)
        ($e.Audit | ConvertTo-Json -Depth 5) | Should -Not -BeLike "*$($t.Substring(0,40))*"
    }
    It 'refuses a callback that is not a POST' {
        (Invoke-PlatformRequest -Platform $e.P -Next { } -Request (New-TestRequest -Path '/assure/auth/callback')).Status | Should -Be 405
    }
}

Describe 'Signing keys' {
    BeforeEach { $e = New-Env }
    It 'refetches once for an unknown kid and then accepts a rotated key' {
        [void](Sign-In $e)                                        # loads the key set
        $e.Pub.Keys = @($e.Key, (New-TestKey 'key-2'))            # Microsoft publishes a new key
        $e.Key2 = $e.Pub.Keys[1]
        $e.Now.T = $e.Now.T.AddMinutes(10)                        # past the refresh limit
        $before = @($e.Pub.Calls).Count
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key2 -Nonce $f.Nonce
        (Send-Callback $e $f $t).Status | Should -Be 302
        @($e.Pub.Calls).Count | Should -BeGreaterThan $before
    }
    It 'limits how often it refreshes for unknown kids' {
        [void](Sign-In $e)
        $e.Now.T = $e.Now.T.AddMinutes(10)
        $stranger = New-TestKey 'not-published'
        $f = Start-Flow $e
        (Send-Callback $e $f (New-TestIdToken -Key $stranger -Nonce $f.Nonce)).Status | Should -Be 400   # one refresh
        $afterFirst = @($e.Pub.Calls).Count
        1..5 | ForEach-Object { $f = Start-Flow $e; [void](Send-Callback $e $f (New-TestIdToken -Key $stranger -Nonce $f.Nonce)) }
        @($e.Pub.Calls).Count | Should -Be $afterFirst                                                    # no more fetches
        (Get-Refusals $e)[-1].Reason | Should -Be 'unknown_kid'
    }
    It 'refuses sign-in when the published metadata names another issuer' {
        $e.Pub.MetaTenant = '99999999-9999-9999-9999-999999999999'
        $f = Start-Flow $e
        (Send-Callback $e $f (New-TestIdToken -Key $e.Key -Nonce $f.Nonce)).Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'keys_unavailable'
    }
}

Describe 'Roles' {
    BeforeEach { $e = New-Env }
    It 'reads roles from the token and keeps only this module''s prefix' {
        $s = Sign-In $e @{ roles = @('Assure.Viewer', 'Assess.Approver', 'Assure.Admin', 'Other.Thing') }
        (Get-Page $e $s.Session).Body | Should -BeLike '*roles=Assure.Admin,Assure.Viewer;*'
    }
    It 'gives no roles when the roles claim is missing' {
        $s = Sign-In $e @{ roles = $null }
        $s.Session | Should -Not -BeNullOrEmpty
        (Get-Page $e $s.Session).Body | Should -BeLike '*roles=;*'
    }
    It 'accepts a single role sent as a string' {
        $s = Sign-In $e @{ roles = 'Assure.Viewer' }
        (Get-Page $e $s.Session).Body | Should -BeLike '*roles=Assure.Viewer;*'
    }
    It 'does not treat a look-alike prefix as the module''s' {
        $s = Sign-In $e @{ roles = @('assure.Admin', 'Assure.', 'XAssure.Admin') }
        (Get-Page $e $s.Session).Body | Should -BeLike '*roles=;*'
    }
}

Describe 'Sessions' {
    BeforeEach { $e = New-Env }
    It 'needs a session (redirects a page, refuses a change)' {
        (Invoke-PlatformRequest -Platform $e.P -Next { } -Request (New-TestRequest -Path '/assure/page')).Headers.Location | Should -Be '/assure/auth/signin'
        (Invoke-PlatformRequest -Platform $e.P -Next { } -Request (New-TestRequest -Method POST -Path '/assure/page')).Status | Should -Be 401
    }
    It 'ends after 8 hours even if used all the time' {
        $s = Sign-In $e
        1..19 | ForEach-Object { $e.Now.T = $e.Now.T.AddMinutes(25); (Get-Page $e $s.Session).Status | Should -Be 200 }   # 475 minutes, never idle
        $e.Now.T = $e.Now.T.AddMinutes(10)
        (Get-Page $e $s.Session).Status | Should -Be 302
        ($e.Audit | Where-Object Event -eq 'SessionExpired').Reason | Should -Be 'absolute'
    }
    It 'ends after 30 minutes idle, and activity keeps it alive' {
        $s = Sign-In $e
        $e.Now.T = $e.Now.T.AddMinutes(25); (Get-Page $e $s.Session).Status | Should -Be 200
        $e.Now.T = $e.Now.T.AddMinutes(25); (Get-Page $e $s.Session).Status | Should -Be 200
        $e.Now.T = $e.Now.T.AddMinutes(31); (Get-Page $e $s.Session).Status | Should -Be 302
        ($e.Audit | Where-Object Event -eq 'SessionExpired').Reason | Should -Be 'idle'
    }
    It 'ignores an unknown session cookie' {
        (Get-Page $e 'made-up').Status | Should -Be 302
    }
    It 'issues a new session id at every sign-in' {
        (Sign-In $e).Session | Should -Not -Be (Sign-In $e).Session
    }
}

Describe 'Anti-forgery' {
    BeforeEach { $e = New-Env; $s = Sign-In $e; $csrf = ((Get-Page $e $s.Session).Body -split 'csrf=')[1] }
    It 'refuses a change with no custom header' {
        (Get-Page $e $s.Session POST @{ 'X-Argus-CSRF' = $csrf }).Status | Should -Be 403
    }
    It 'refuses a change with no anti-forgery token' {
        (Get-Page $e $s.Session POST @{ 'X-Argus-Request' = '1' }).Status | Should -Be 403
    }
    It 'refuses a change with the wrong anti-forgery token' {
        (Get-Page $e $s.Session POST @{ 'X-Argus-Request' = '1'; 'X-Argus-CSRF' = 'wrong' }).Status | Should -Be 403
    }
    It 'refuses another session''s anti-forgery token' {
        $other = Sign-In $e
        $otherCsrf = ((Get-Page $e $other.Session).Body -split 'csrf=')[1]
        (Get-Page $e $s.Session POST @{ 'X-Argus-Request' = '1'; 'X-Argus-CSRF' = $otherCsrf }).Status | Should -Be 403
    }
    It 'accepts a change with the header and the right token' {
        (Get-Page $e $s.Session POST @{ 'X-Argus-Request' = '1'; 'X-Argus-CSRF' = $csrf }).Status | Should -Be 200
    }
    It 'does not need a token for a read' {
        (Get-Page $e $s.Session).Status | Should -Be 200
    }
}

Describe 'Spoofed identity headers' {
    BeforeEach { $e = New-Env }
    BeforeAll { $spoof = @{ 'X-Forwarded-User' = 'admin'; 'X-Remote-User' = 'admin'; 'X-MS-CLIENT-PRINCIPAL-NAME' = 'admin@x.test'; 'X-User' = 'admin'; 'X-Roles' = 'Assure.Admin'; 'REMOTE_USER' = 'admin' } }
    It 'gives no access without a session' {
        $r = Invoke-PlatformRequest -Platform $e.P -Next { New-PlatformResponse 200 'in' } -Request (New-TestRequest -Path '/assure/page' -Headers $spoof)
        $r.Status | Should -Be 302
    }
    It 'does not change who the session says the person is' {
        $s = Sign-In $e @{ roles = @('Assure.Viewer') }
        $r = Get-Page $e $s.Session GET $spoof
        $r.Body | Should -BeLike "who=$script:Oid;name=Test Person;roles=Assure.Viewer;*"
    }
    It 'uses X-Forwarded-For only for the audit address (rightmost entry)' {
        $f = Start-Flow $e
        $t = New-TestIdToken -Key $e.Key -Nonce $f.Nonce
        $body = "id_token=$([Uri]::EscapeDataString($t))&state=$($f.State)"
        [void](Invoke-PlatformRequest -Platform $e.P -Next { } -Request (New-TestRequest -Method POST -Path '/assure/auth/callback' -Cookies @{ argus_pre = $f.Pre } -Body $body -Headers @{ 'X-Forwarded-For' = '6.6.6.6, 203.0.113.9' }))
        ($e.Audit | Where-Object Event -eq 'SignIn').ClientAddress | Should -Be '203.0.113.9'
    }
}

Describe 'Sign out' {
    BeforeEach { $e = New-Env; $s = Sign-In $e; $csrf = ((Get-Page $e $s.Session).Body -split 'csrf=')[1] }
    It 'ends the server session, audits it, and sends the browser to Entra' {
        $r = Get-Page $e $s.Session POST @{ 'X-Argus-Request' = '1'; 'X-Argus-CSRF' = $csrf } -Path '/assure/auth/signout'
        $r.Status | Should -Be 303
        $r.Headers.Location | Should -BeLike "https://login.microsoftonline.com/$script:Tenant/oauth2/v2.0/logout*"
        $r.SetCookies[0] | Should -Match 'Max-Age=0'
        (Get-Page $e $s.Session).Status | Should -Be 302
        ($e.Audit | Where-Object Event -eq 'SignOut').Oid | Should -Be $script:Oid
    }
    It 'does not sign out on a forged request' {
        (Get-Page $e $s.Session POST @{ 'X-Argus-Request' = '1' } -Path '/assure/auth/signout').Status | Should -Be 403
        (Get-Page $e $s.Session).Status | Should -Be 200
    }
}

Describe 'Fresh sign-in' {
    BeforeEach { $e = New-Env }
    It 'is not fresh after an ordinary sign-in' {
        $s = Sign-In $e
        $sess = $e.P.Sessions.Values | Select-Object -First 1
        Test-PlatformFreshSignIn $e.P $sess | Should -BeFalse
    }
    It 'becomes fresh after the forced route, re-reads roles, and audits a role change' {
        $s = Sign-In $e @{ roles = @('Assure.Viewer') }
        $r = Invoke-PlatformRequest -Platform $e.P -Next { } -Request (New-TestRequest -Path '/assure/auth/fresh' -Cookies @{ argus_session = $s.Session })
        $r.Status | Should -Be 302
        $r.Headers.Location | Should -BeLike '*authorize?*'
        $nonce = Get-QueryValue $r.Headers.Location 'nonce'; $state = Get-QueryValue $r.Headers.Location 'state'
        $t = New-TestIdToken -Key $e.Key -Nonce $nonce -Claims @{ roles = @('Assure.Admin') }
        $cb = Send-Callback $e @{ Pre = (Get-CookieValue $r 'argus_pre'); State = $state } $t
        $cb.Status | Should -Be 302
        $new = Get-CookieValue $cb 'argus_session'
        $new | Should -Not -Be $s.Session
        (Get-Page $e $s.Session).Status | Should -Be 302                       # old id is gone
        (Get-Page $e $new).Body | Should -BeLike '*roles=Assure.Admin;*'
        $sess = $e.P.Sessions.Values | Select-Object -First 1
        Test-PlatformFreshSignIn $e.P $sess | Should -BeTrue
        $e.Now.T = $e.Now.T.AddMinutes(16)
        Test-PlatformFreshSignIn $e.P $sess | Should -BeFalse
        $chg = $e.Audit | Where-Object Event -eq 'RoleChange'
        $chg.Before | Should -Be 'Assure.Viewer'; $chg.After | Should -Be 'Assure.Admin'
    }
    It 'refuses a fresh sign-in by a different person' {
        $s = Sign-In $e
        $r = Invoke-PlatformRequest -Platform $e.P -Next { } -Request (New-TestRequest -Path '/assure/auth/fresh' -Cookies @{ argus_session = $s.Session })
        $t = New-TestIdToken -Key $e.Key -Nonce (Get-QueryValue $r.Headers.Location 'nonce') -Claims @{ oid = '44444444-4444-4444-4444-444444444444' }
        (Send-Callback $e @{ Pre = (Get-CookieValue $r 'argus_pre'); State = (Get-QueryValue $r.Headers.Location 'state') } $t).Status | Should -Be 400
        (Get-Refusals $e).Reason | Should -Be 'fresh_signin_other_person'
    }
}

Describe 'Audit hook' {
    It 'fails closed: no session is made if the audit callback throws' {
        $e = New-Env
        $e.P.Audit = { throw 'disk full' }
        $f = Start-Flow $e
        $r = Send-Callback $e $f (New-TestIdToken -Key $e.Key -Nonce $f.Nonce)
        $r.Status | Should -Be 503
        $e.P.Sessions.Count | Should -Be 0
    }
}
