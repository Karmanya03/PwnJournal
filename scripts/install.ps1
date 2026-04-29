Write-Host "[+] Installing PwnJournal via Cargo..." -ForegroundColor Cyan
cargo install --locked --git https://github.com/Karmanya03/PwnJournal.git --tag v0.1.0

Write-Host "[+] Creating system-wide directory in Program Files..." -ForegroundColor Cyan
$binDir = Join-Path $env:ProgramFiles 'PwnJournal\bin'
New-Item -ItemType Directory -Force $binDir | Out-Null

Write-Host "[+] Copying executables..." -ForegroundColor Cyan
Copy-Item (Join-Path $HOME '.cargo\bin\pwnj.exe') $binDir -Force
Copy-Item (Join-Path $HOME '.cargo\bin\pwnjournal.exe') $binDir -Force

Write-Host "[+] Updating Machine PATH..." -ForegroundColor Cyan
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($machinePath -notlike "*$binDir*") { 
    [Environment]::SetEnvironmentVariable('Path', "$machinePath;$binDir", 'Machine') 
    Write-Host "    -> PATH updated successfully." -ForegroundColor Green
} else {
    Write-Host "    -> PATH already contains PwnJournal." -ForegroundColor Yellow
}

Write-Host "[+] Done! You can now run 'pwnj --help' in a new terminal." -ForegroundColor Green
