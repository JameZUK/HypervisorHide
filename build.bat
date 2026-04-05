@echo off
setlocal enabledelayedexpansion

:: Find MSVC version
set "VCDIR=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC"
for /f "delims=" %%i in ('dir /b /ad "%VCDIR%"') do set "MSVC_VER=%%i"
set "VCTOOLS=%VCDIR%\%MSVC_VER%"

:: WDK paths
set "WDK=C:\Program Files (x86)\Windows Kits\10"
set "WDKVER=10.0.22621.0"

set "BDIR=%~dp0build"
if not exist "%BDIR%" mkdir "%BDIR%"

echo [*] MSVC: %MSVC_VER%
echo [*] WDK:  %WDKVER%
echo.

:: Set PATH so cl.exe and link.exe are found directly
set "PATH=%VCTOOLS%\bin\Hostx64\x64;%PATH%"

:: Include paths
set "INCS=-I"%VCTOOLS%\include" -I"%WDK%\Include\%WDKVER%\km" -I"%WDK%\Include\%WDKVER%\shared" -I"%WDK%\Include\%WDKVER%\ucrt" -I"%~dp0capstone\include""

:: Lib paths
set "LIBPATHS=/LIBPATH:"%VCTOOLS%\lib\x64" /LIBPATH:"%WDK%\lib\%WDKVER%\km\x64" /LIBPATH:"%WDK%\lib\%WDKVER%\ucrt\x64""

:: Common defines
set "DEFS=/D_AMD64_ /DAMD64 /D_WIN64 /DNDEBUG /DCAPSTONE_HAS_X86 /DCAPSTONE_USE_SYS_DYN_MEM /DCAPSTONE_DIET /DCAPSTONE_X86_ATT_DISABLE"

:: Kernel C++ flags
set "CXXFLAGS=/kernel /O2 /W3 /WX- /GS- /Gy /Zp8 /Zi /std:c++17 %DEFS%"
:: Kernel C flags (no /std:c++17, no /kernel for some C files)
set "CCFLAGS=/kernel /O2 /W3 /WX- /GS- /Gy /Zp8 %DEFS%"

:: Compile C++ driver sources
echo [1/3] Compiling main.cpp...
cl.exe /c %CXXFLAGS% %INCS% /Fo"%BDIR%\main.obj" "%~dp0HypervisorHide\main.cpp"
if !errorlevel! neq 0 goto :error

echo [2/3] Compiling locate_firmware.cpp...
cl.exe /c %CXXFLAGS% %INCS% /Fo"%BDIR%\locate_firmware.obj" "%~dp0HypervisorHide\locate_firmware.cpp"
if !errorlevel! neq 0 goto :error

:: Compile C sources
echo [3/3] Compiling Capstone + cs_driver_mm...
cl.exe /c %CCFLAGS% %INCS% /Fo"%BDIR%\cs_driver_mm.obj" "%~dp0HypervisorHide\cs_driver_mm.c"
if !errorlevel! neq 0 goto :error

for %%f in (cs MCInst MCInstrDesc MCRegisterInfo Mapping SStream utils) do (
    cl.exe /c %CCFLAGS% %INCS% /Fo"%BDIR%\%%f.obj" "%~dp0capstone\%%f.c"
    if !errorlevel! neq 0 goto :error
)
for %%f in (X86Disassembler X86DisassemblerDecoder X86IntelInstPrinter X86InstPrinterCommon X86Mapping X86Module) do (
    cl.exe /c %CCFLAGS% %INCS% /Fo"%BDIR%\%%f.obj" "%~dp0capstone\arch\X86\%%f.c"
    if !errorlevel! neq 0 goto :error
)

:: Link
echo.
echo [*] Linking HypervisorHide.sys...
link.exe /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry ^
    /OUT:"%BDIR%\HypervisorHide.sys" ^
    /PDB:"%BDIR%\HypervisorHide.pdb" ^
    %LIBPATHS% ^
    ntoskrnl.lib hal.lib fltmgr.lib BufferOverflowFastFailK.lib ^
    "%BDIR%\main.obj" "%BDIR%\locate_firmware.obj" "%BDIR%\cs_driver_mm.obj" ^
    "%BDIR%\cs.obj" "%BDIR%\MCInst.obj" "%BDIR%\MCInstrDesc.obj" ^
    "%BDIR%\MCRegisterInfo.obj" "%BDIR%\Mapping.obj" "%BDIR%\SStream.obj" ^
    "%BDIR%\utils.obj" "%BDIR%\X86Disassembler.obj" "%BDIR%\X86DisassemblerDecoder.obj" ^
    "%BDIR%\X86IntelInstPrinter.obj" "%BDIR%\X86InstPrinterCommon.obj" ^
    "%BDIR%\X86Mapping.obj" "%BDIR%\X86Module.obj"

if !errorlevel! neq 0 goto :error

echo.
echo [+] Build successful!
dir "%BDIR%\HypervisorHide.sys"
goto :end

:error
echo.
echo [!] Build FAILED
exit /b 1

:end
endlocal
