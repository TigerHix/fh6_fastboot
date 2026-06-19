# Build FH6 FastBoot (release) and assemble a distributable zip in dist/.
# Usage:  pwsh ./package.ps1
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

cargo build --release --manifest-path (Join-Path $root 'Cargo.toml')

$stage = Join-Path $root 'dist\FH6-FastBoot'
Remove-Item (Join-Path $root 'dist') -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $stage | Out-Null

Copy-Item (Join-Path $root 'target\release\version.dll') $stage
Copy-Item (Join-Path $root 'fastboot.ini') $stage

$zip = Join-Path $root 'dist\FH6-FastBoot.zip'
Compress-Archive -Path "$stage\*" -DestinationPath $zip -Force
Write-Host "Packaged: $zip"
Get-ChildItem $stage | Select-Object Name, Length
