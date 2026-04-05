# HypervisorHide

A Windows x64 kernel driver that hides virtual machine indicators from the guest OS. Works on **any hypervisor** — KVM/QEMU, VMware, VirtualBox, Hyper-V, Xen, Parallels.

Adapted from [VmwareHardenedLoader](https://github.com/hzqst/VmwareHardenedLoader) and extended to cover all major hypervisors in a single driver.

## What It Does

Commercial software protection systems (VMProtect, Themida, anti-cheat engines) detect virtual machines by querying firmware tables via `NtQuerySystemInformation(SystemFirmwareTableInformation)`. These tables contain hypervisor-specific strings that identify the virtual environment.

HypervisorHide hooks the Windows kernel's firmware table providers (ACPI, RSMB, FIRM) and scrubs all known hypervisor indicator strings from the returned data. This operates below the syscall level — even direct `syscall` stubs (used by VMProtect) go through the kernel's firmware table handler, which our driver intercepts.

## Detection Vectors Addressed

### KVM / QEMU / Proxmox

| Table | Indicator | Description |
|-------|-----------|-------------|
| ACPI | `BOCHS`, `BXPC` | QEMU default ACPI OEM ID and table ID |
| SMBIOS | `QEMU` | SMBIOS system manufacturer |
| SMBIOS | `Proxmox` | Proxmox OVMF firmware branding |
| SMBIOS | `EDK II` | UEFI firmware identifier |
| SMBIOS | `SeaBIOS` | BIOS firmware identifier |
| SMBIOS | `KVMKVMKVM` | KVM CPUID vendor string (cached in firmware) |
| All | `Red Hat`, `VirtIO` | Red Hat / VirtIO device identifiers |

### VMware

| Table | Indicator | Description |
|-------|-----------|-------------|
| ACPI | `VMware` | VMware ACPI OEM ID |
| SMBIOS | `VMware`, `VMWARE` | VMware system manufacturer |
| FIRM | `VMware` | VMware firmware identifier |
| All | `Virtual Platform` | VMware product name |

### VirtualBox

| Table | Indicator | Description |
|-------|-----------|-------------|
| ACPI | `VBOX` | VirtualBox ACPI identifiers |
| SMBIOS | `VirtualBox`, `innotek` | VirtualBox system info |
| All | `Oracle` | Oracle Corporation (VirtualBox parent) |

### Hyper-V

| Table | Indicator | Description |
|-------|-----------|-------------|
| SMBIOS | `Hyper-V` | Hyper-V product string |
| SMBIOS | `Microsoft Corporation` | Hyper-V manufacturer |
| All | `Virtual Machine` | Generic VM product name |

### Xen / Parallels

| Table | Indicator | Description |
|-------|-----------|-------------|
| SMBIOS | `Xen`, `xen` | Xen hypervisor |
| SMBIOS | `Parallels` | Parallels Desktop |
| SMBIOS | `prl_` | Parallels driver prefix |

## Why a Kernel Driver?

Usermode tools (Frida, API hooks) can intercept `GetSystemFirmwareTable()` and scrub strings. But:

1. **VMProtect makes direct syscalls** — its own `syscall` stubs bypass ntdll.dll entirely, making usermode hooks invisible
2. **OVMF firmware branding** ("Proxmox distribution of EDK II") is a compile-time constant that cannot be changed via hypervisor configuration
3. **Some strings are generated at runtime** by firmware, not stored as patchable static data

The kernel driver hooks at the firmware table provider level — below syscalls, above the actual firmware tables. Every query path goes through our hooks.

## Requirements

- Windows 10/11 x64
- Windows Driver Kit (WDK) for building
- Test Signing mode enabled for loading unsigned drivers

## Building

### Prerequisites

1. Install [Visual Studio 2022](https://visualstudio.microsoft.com/) with C++ Desktop workload
2. Install [Windows Driver Kit (WDK)](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

### Build

```
msbuild HypervisorHide.sln /p:Configuration=Release /p:Platform=x64
```

Or open in Visual Studio and build.

## Installation

### Enable Test Signing (one-time)

```powershell
bcdedit /set testsigning on
# Reboot required
```

### Load the Driver

```powershell
copy HypervisorHide.sys C:\Windows\System32\drivers\
sc create HypervisorHide type=kernel binPath=C:\Windows\System32\drivers\HypervisorHide.sys
sc start HypervisorHide
```

### Auto-Start on Boot

```powershell
sc config HypervisorHide start=boot
```

### Verify

```powershell
# Before:
(Get-CimInstance Win32_BIOS).BIOSVersion
# "BOCHS - 1", "Proxmox distribution of EDK II - 10000"

# After:
(Get-CimInstance Win32_BIOS).BIOSVersion
# Hypervisor strings replaced with spaces
```

### Unload

```powershell
sc stop HypervisorHide
sc delete HypervisorHide
```

## How It Works

1. **Locate kernel structures**: Disassembles the `PAGE` section of ntoskrnl.exe using Capstone, pattern-matching `mov r8d, 'TFRA'` to find `ExpFirmwareTableResource` and `ExpFirmwareTableProviderListHead`
2. **Hook firmware table providers**: Acquires `ExpFirmwareTableResource` exclusively, walks the provider linked list, replaces handlers for ACPI, RSMB, and FIRM providers
3. **Scrub on query**: When any process queries firmware tables, our handler calls the original, then searches the returned buffer for all known hypervisor indicator strings and overwrites them with spaces (preserving buffer layout)
4. **Clean unload**: `DriverUnload` restores original handler pointers

## Complementary Hypervisor Configuration

### Proxmox / KVM

```
cpu: host,hidden=1
balloon: 0
agent: 0
vmgenid: 0
scsihw: lsi
vga: std
net0: e1000=D4:BE:D9:12:34:56,bridge=vmbr0
args: -smbios type=0,vendor=Dell\ Inc.,version=1.14.0 -smbios type=1,manufacturer=Dell,product=Latitude-5520 -global scsi-hd.vendor=WDC -global scsi-hd.product=WD10EZEX -machine x-oem-id=ALASKA,x-oem-table-id=A_M_I___
```

### VMware

```
hypervisor.cpuid.v0 = "FALSE"
smbios.reflectHost = "TRUE"
board-id.reflectHost = "TRUE"
```

### VirtualBox

```bash
VBoxManage modifyvm "VMName" --paravirtprovider none
```

The driver handles what hypervisor configuration cannot: runtime-generated firmware strings.

## Credits

- Original concept and VMware implementation: [hzqst/VmwareHardenedLoader](https://github.com/hzqst/VmwareHardenedLoader)
- Universal hypervisor adaptation: Arkana Project
- Capstone disassembly engine: [aquynh/capstone](https://github.com/aquynh/capstone)

## Licence

MIT
