Write-Host "[+] Downloading latest PwnJournal release..." -ForegroundColor Cyan
$installDir = Join-Path $HOME '.cargo\bin'
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Force $installDir | Out-Null
}
$archive = Join-Path $env:TEMP 'PwnJournal-latest.zip'
Invoke-WebRequest 'https://github.com/Karmanya03/PwnJournal/releases/latest/download/PwnJournal-windows-x64.zip' -OutFile $archive

Write-Host "[+] Extracting to $installDir..." -ForegroundColor Cyan
Expand-Archive $archive -DestinationPath $installDir -Force

Write-Host "[+] Done! You can now run 'pwnj --help'." -ForegroundColor Green
