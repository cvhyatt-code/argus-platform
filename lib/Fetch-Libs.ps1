<#
.SYNOPSIS
  Downloads the pinned token-validation libraries into lib/ and checks each against lib/manifest.json.
.DESCRIPTION
  Normal run: downloads each package from nuget.org, takes the net8.0 DLL, and refuses (deletes it, exits 1)
  unless its SHA-256 equals the manifest. Use -Update to print the hashes for a new version; the manifest is then
  edited by hand and the change reviewed. Nothing is trusted unless it matches the manifest.
#>
[CmdletBinding()]
param([switch]$Update)
$ErrorActionPreference = 'Stop'
$libDir = $PSScriptRoot
$manifestPath = Join-Path $libDir 'manifest.json'
$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("argus-libs-" + [guid]::NewGuid())
New-Item -ItemType Directory $tmp | Out-Null
try {
    foreach ($f in $manifest.files) {
        $url = "$($manifest.source)/$($f.package)/$($f.version)/$($f.package).$($f.version).nupkg"
        $pkg = Join-Path $tmp "$($f.package).zip"
        Invoke-WebRequest -Uri $url -OutFile $pkg -TimeoutSec 120
        $dir = Join-Path $tmp $f.package
        Expand-Archive $pkg $dir
        $dll = Join-Path $dir "lib/net8.0/$($f.file)"
        $hash = (Get-FileHash $dll -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($Update) { "{0}  {1}" -f $hash, $f.file; continue }
        if ($hash -ne $f.sha256) { throw "SHA-256 mismatch for $($f.file): expected $($f.sha256), got $hash. Not installed." }
        Copy-Item $dll (Join-Path $libDir $f.file) -Force
        "OK  $($f.file)  $hash"
    }
} finally { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
