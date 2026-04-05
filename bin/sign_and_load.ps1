# Run as Administrator on the Windows VM console (not SSH)
# Signs and loads HypervisorHide.sys in DEBUG mode (no hooking, just logging)

$ErrorActionPreference = "Stop"

Write-Host "[*] Creating certificate..." -ForegroundColor Cyan
try {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=HvHide" -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(10)
    Write-Host "[+] Cert: $($cert.Thumbprint)" -ForegroundColor Green
} catch {
    Write-Host "[*] Cert may already exist, continuing..." -ForegroundColor Yellow
}

Write-Host "[*] Trusting certificate..."
Export-Certificate -Cert (Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert | Select -First 1) -FilePath C:\Malware\hv.cer | Out-Null
certutil -addstore Root C:\Malware\hv.cer 2>&1 | Out-Null
certutil -addstore TrustedPublisher C:\Malware\hv.cer 2>&1 | Out-Null

Write-Host "[*] Copying and signing driver..."
Copy-Item C:\Malware\HypervisorHide\build\HypervisorHide.sys C:\Windows\System32\drivers\HypervisorHide.sys -Force
& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe" sign /fd sha256 /sm /s My /n HvHide C:\Windows\System32\drivers\HypervisorHide.sys 2>&1

Write-Host "[*] Loading driver (DEBUG MODE - safe, no hooking)..."
sc.exe delete HypervisorHide 2>$null
sc.exe create HypervisorHide type=kernel binPath=C:\Windows\System32\drivers\HypervisorHide.sys
$result = sc.exe start HypervisorHide 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Driver loaded!" -ForegroundColor Green
} else {
    Write-Host "[!] Start result: $result" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Debug output (check for Resource/ListHead addresses) ===" -ForegroundColor Yellow
# Give driver a moment to log
Start-Sleep 2
Get-WinEvent -LogName System -MaxEvents 20 | Where-Object { $_.ProviderName -eq "Microsoft-Windows-Kernel-General" -or $_.Message -match "HypervisorHide" } | Select TimeCreated, Message | Format-List

Write-Host "=== Also check DebugView (Sysinternals) for kernel DbgPrint output ===" -ForegroundColor Yellow
pause
