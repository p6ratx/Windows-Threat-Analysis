$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
New-Item -ItemType Directory -Force -Path bin | Out-Null

Push-Location collectors\go-net
go build -o ..\..\bin\go-net.exe .
Pop-Location

Push-Location collectors\rust-host
cargo build --release --target-dir "$Root\collectors\rust-host\target"
Copy-Item "$Root\collectors\rust-host\target\release\aegis-rust-host.exe" "$Root\bin\rust-host.exe" -Force
Pop-Location

Push-Location collectors\rust-etw
cargo build --release --target-dir "$Root\collectors\rust-etw\target"
Copy-Item "$Root\collectors\rust-etw\target\release\aegis-rust-etw.exe" "$Root\bin\rust-etw.exe" -Force
Pop-Location

Write-Host "Built bin/go-net.exe, bin/rust-host.exe, bin/rust-etw.exe"
