@echo off
echo [*] Installing HypervisorHide driver...

:: Check admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Run as Administrator
    pause
    exit /b 1
)

:: Copy driver
copy /y "%~dp0HypervisorHide.sys" "%SystemRoot%\System32\drivers\HypervisorHide.sys"
if %errorlevel% neq 0 (
    echo [!] Failed to copy driver
    pause
    exit /b 1
)

:: Create service
sc create HypervisorHide type=kernel binPath="%SystemRoot%\System32\drivers\HypervisorHide.sys"
if %errorlevel% neq 0 (
    echo [!] Service already exists or creation failed
)

:: Start service
sc start HypervisorHide
if %errorlevel% neq 0 (
    echo [!] Driver failed to start. Check test signing: bcdedit /set testsigning on
    pause
    exit /b 1
)

echo [+] HypervisorHide loaded successfully
echo.
echo Verify: powershell -Command "(Get-CimInstance Win32_BIOS).BIOSVersion"
pause
