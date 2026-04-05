@echo off
echo [*] Uninstalling HypervisorHide driver...

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Run as Administrator
    pause
    exit /b 1
)

sc stop HypervisorHide
sc delete HypervisorHide
del /f "%SystemRoot%\System32\drivers\HypervisorHide.sys" 2>nul

echo [+] HypervisorHide removed
pause
