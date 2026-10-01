# Test helpers. The RSA key pair is generated in memory for each run: no key, public or private, is committed.
# tests/fixtures/metadata.template.json is the fake metadata document; the key set is built from the generated key.
Set-StrictMode -Version Latest
$script:Tenant = '11111111-1111-1111-1111-111111111111'
$script:Client = '22222222-2222-2222-2222-222222222222'
$script:Oid    = '33333333-3333-3333-3333-333333333333'

function New-TestKey {
    param([string]$Kid = 'key-1')
    $rsa = [Security.Cryptography.RSA]::Create(2048)
    @{ Rsa = $rsa; Kid = $Kid }
}

function ConvertTo-Base64Url { param([byte[]]$Bytes) [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') }

function Get-TestJwks {
    param([hashtable[]]$Keys)
    $b64 = { param([byte[]]$Bytes) [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
    $items = foreach ($k in $Keys) {
        $p = $k.Rsa.ExportParameters($false)
        @{ kty = 'RSA'; use = 'sig'; alg = 'RS256'; kid = $k.Kid; n = (& $b64 $p.Modulus); e = (& $b64 $p.Exponent) }
    }
    @{ keys = @($items) } | ConvertTo-Json -Depth 5 -Compress
}

function New-TestFetcher {
    # Counts calls so tests can check refresh limits. $State.Keys is the key set currently "published".
    param([hashtable]$State, [string]$Tenant = $script:Tenant)
    $template = Get-Content (Join-Path $PSScriptRoot 'fixtures/metadata.template.json') -Raw
    $jwks = ${function:Get-TestJwks}
    {
        param($Uri)
        $State.Calls += $Uri
        if ($Uri -like '*openid-configuration') { return $template.Replace('{tenant}', $State.MetaTenant) }
        if ($Uri -like '*discovery/v2.0/keys') { return & $jwks $State.Keys }
        throw "unexpected fetch $Uri"
    }.GetNewClosure()
}

function New-TestIdToken {
    param(
        [hashtable]$Key, [string]$Nonce, [hashtable]$Claims = @{},
        [string]$Alg = 'RS256', [string]$Kid, [switch]$Tamper
    )
    $now = [DateTimeOffset]::UtcNow
    $body = [ordered]@{
        iss = "https://login.microsoftonline.com/$script:Tenant/v2.0"; aud = $script:Client; tid = $script:Tenant
        oid = $script:Oid; name = 'Test Person'; nonce = $Nonce
        nbf = $now.AddMinutes(-1).ToUnixTimeSeconds(); iat = $now.AddMinutes(-1).ToUnixTimeSeconds(); exp = $now.AddHours(1).ToUnixTimeSeconds()
        roles = @('Assure.Editor')
    }
    foreach ($k in $Claims.Keys) { if ($null -eq $Claims[$k]) { $body.Remove($k) } else { $body[$k] = $Claims[$k] } }
    $kidValue = if ($Kid) { $Kid } else { $Key.Kid }
    $header = [ordered]@{ alg = $Alg; typ = 'JWT'; kid = $kidValue }
    $h = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes(($header | ConvertTo-Json -Compress)))
    $b = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json -Compress)))
    $signing = [Text.Encoding]::ASCII.GetBytes("$h.$b")
    switch ($Alg) {
        'none'  { return "$h.$b." }
        'HS256' { $sig = [Security.Cryptography.HMACSHA256]::HashData([byte[]](1..32), $signing) }
        default { $sig = $Key.Rsa.SignData($signing, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1) }
    }
    if ($Tamper) {
        $b2 = [ordered]@{} + $body; $b2.name = 'Someone Else'
        $b = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes(($b2 | ConvertTo-Json -Compress)))
    }
    "$h.$b.$(ConvertTo-Base64Url $sig)"
}

function New-TestRequest {
    param([string]$Method = 'GET', [string]$Path, [hashtable]$Headers = @{}, [hashtable]$Cookies = @{}, [string]$Body = '', [string]$Remote = '127.0.0.1')
    $h = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] }
    if ($Method -eq 'POST' -and $Body -and -not $h.ContainsKey('Content-Type')) { $h['Content-Type'] = 'application/x-www-form-urlencoded' }
    [pscustomobject]@{ Method = $Method; Path = $Path; Headers = $h; Cookies = $Cookies; Body = $Body; Form = $null; RemoteAddress = $Remote }
}

function Get-CookieValue {
    param($Response, [string]$Name)
    foreach ($c in $Response.SetCookies) { if ($c -like "$Name=*") { return ($c -split ';')[0].Substring($Name.Length + 1) } }
}

function Get-QueryValue {
    param([string]$Url, [string]$Name)
    $q = ([Uri]$Url).Query.TrimStart('?')
    foreach ($pair in $q -split '&') { $kv = $pair -split '=', 2; if ($kv[0] -eq $Name) { return [Uri]::UnescapeDataString($kv[1]) } }
}
