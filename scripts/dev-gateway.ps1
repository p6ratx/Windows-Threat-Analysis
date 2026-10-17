$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
New-Item -ItemType Directory -Force -Path bin, data | Out-Null
Push-Location gateway
if (-not (Test-Path node_modules)) { npm install }
npm run migrate
Pop-Location
Write-Host "Starting gateway on :8787 ..."
Set-Location gateway
npm run dev
