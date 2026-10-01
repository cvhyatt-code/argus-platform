<#
.SYNOPSIS
  Starts the real listener on 127.0.0.1 with a made-up (not real) tenant and client, and shows what a browser would
  receive. No network, no sign-in, no secrets: it only shows the sign-in redirect, the pre-sign-in cookie, and that a
  page without a session is bounced. Use it to see the front door working before Entra is involved.
#>
[CmdletBinding()]
param([int]$Port = 18443)
$ErrorActionPreference = 'Stop'
$module = Join-Path $PSScriptRoot '../src/ArgusPlatform.psm1'
Import-Module $module -Force
$p = New-Platform -Audit { param($r) } -Config @{
    TenantId = '11111111-1111-1111-1111-111111111111'; ClientId = '22222222-2222-2222-2222-222222222222'
    ModulePath = '/assure'; RolePrefix = 'Assure.'; RedirectUri = "http://localhost:$Port/assure/auth/callback" }
$stop = [hashtable]::Synchronized(@{ Stop = $false })
$job = Start-ThreadJob { param($p, $stop, $module, $port)
    Import-Module $module -Force
    Start-PlatformServer -Platform $p -Prefixes "http://127.0.0.1:$port/" -Stop $stop -Next { New-PlatformResponse 200 'ok' }
} -ArgumentList $p, $stop, (Resolve-Path $module).Path, $Port
try {
    Start-Sleep -Seconds 2
    $base = "http://127.0.0.1:$Port"
    "1. GET $base/assure/auth/signin  (expect 302 to login.microsoftonline.com, and an argus_pre cookie)"
    curl -s -i --max-time 5 "$base/assure/auth/signin" | Select-Object -First 8
    ''
    "2. GET $base/assure/page with no session  (expect 302 back to /assure/auth/signin)"
    curl -s -o /dev/null -w "%{http_code} %{redirect_url}`n" --max-time 5 "$base/assure/page"
    "3. POST $base/assure/page with no session  (expect 401)"
    curl -s -o /dev/null -w "%{http_code}`n" --max-time 5 -X POST -d "" "$base/assure/page"
    "4. GET $base/other  (expect 404: outside the module path)"
    curl -s -o /dev/null -w "%{http_code}`n" --max-time 5 "$base/other"
    ''
    "5. Binding to anything but 127.0.0.1 is refused:"
    try { Start-PlatformServer -Platform $p -Prefixes 'http://+:8443/' -Next { } } catch { "   $($_.Exception.Message)" }
} finally {
    $stop.Stop = $true
    Receive-Job $job -Wait -ErrorAction SilentlyContinue | Out-Null
}
