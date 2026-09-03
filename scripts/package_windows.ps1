param(
    [string]$BuildDir = "build-windows"
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Exe = Join-Path $Root "$BuildDir\lethe-win.exe"
$Dist = Join-Path $Root "dist"
$Stage = Join-Path $Dist "Lethe-windows-x64"

# Keep the package name tied to the CMake project version instead of allowing
# a release bump to silently produce an old-version artifact name.
$CMake = Get-Content (Join-Path $Root "CMakeLists.txt") -Raw
$VersionMatch = [regex]::Match($CMake, 'project\(lethe\s+VERSION\s+([0-9.]+)')
if (-not $VersionMatch.Success) {
    throw "Unable to determine Lethe version from CMakeLists.txt"
}
$Version = $VersionMatch.Groups[1].Value
$Zip = Join-Path $Dist "Lethe-$Version-windows-x64.zip"

if (-not (Test-Path $Exe)) {
    throw "Missing $Exe. Configure/build the Windows target first."
}

Remove-Item $Stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $Stage -Force | Out-Null
Copy-Item $Exe (Join-Path $Stage "Lethe.exe")

@"
Lethe $Version - Windows x64

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
