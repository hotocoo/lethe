param(
    [string]$BuildDir = "build-windows"
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Exe = Join-Path $Root "$BuildDir\lethe-win.exe"
$Dist = Join-Path $Root "dist"
$Stage = Join-Path $Dist "Lethe-windows-x64"
$Zip = Join-Path $Dist "Lethe-1.3.4-windows-x64.zip"

if (-not (Test-Path $Exe)) {
    throw "Missing $Exe. Configure/build the Windows target first."
}

Remove-Item $Stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $Stage -Force | Out-Null
Copy-Item $Exe (Join-Path $Stage "Lethe.exe")

@"
Lethe 1.3.4 - Windows x64

This package contains the Lethe host executable. Microsoft Edge WebView2
Evergreen Runtime must be installed on the machine; Lethe does not bundle a
second browser runtime or silently replace Microsoft's managed runtime.

The host enforces Lethe's navigation/private-network/tracker policy and keeps
its WebView2 profile under the user's LocalAppData\Lethe\WebView2 directory.

Built-in raster scaling is available with LETHE_RASTER_SCALE in the range
0.66..2.0 and Ctrl+Alt+Left/Right while the browser is focused.
"@ | Set-Content -Encoding UTF8 (Join-Path $Stage "README.txt")

if (Test-Path $Zip) { Remove-Item $Zip -Force }
Compress-Archive -Path (Join-Path $Stage "*") -DestinationPath $Zip -CompressionLevel Optimal

Write-Host "[pkg] wrote $Zip"
