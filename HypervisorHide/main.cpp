/*
 * HypervisorHide - Universal VM firmware table scrubber
 *
 * Hooks Windows kernel firmware table providers (ACPI, RSMB, FIRM) and
 * scrubs hypervisor indicator strings from query results. Works on
 * KVM/QEMU, VMware, VirtualBox, Hyper-V, Xen, and Parallels.
 *
 * Adapted from VmwareHardenedLoader (hzqst) for universal hypervisor support.
 *
 * How it works:
 *   1. Finds ExpFirmwareTableResource and ExpFirmwareTableProviderListHead
 *      by disassembling ntoskrnl's PAGE section with Capstone
 *   2. Hooks ACPI, RSMB, and FIRM firmware table handlers
 *   3. Each hook calls the original handler, then scrubs the returned buffer
 *   4. DriverUnload restores the original handlers
 */

#include <fltkernel.h>
#include <ntimage.h>
#include "cs_driver_mm.h"

/* Set to 1 to only log what would be hooked, without actually hooking. */
#define HYPERVISORHIDE_DEBUG_ONLY 0

/* Set to 1 to skip ALL driver logic and just return SUCCESS (bare minimum test) */
/* Set to 1 for hardcoded addresses (Win11 26200 only), bypasses Capstone */
#define HYPERVISORHIDE_HARDCODED 1
#define HYPERVISORHIDE_STUB_ONLY 0

extern "C"
{

/* ------------------------------------------------------------------ */
/*  Hypervisor indicator strings to scrub                              */
/* ------------------------------------------------------------------ */

/*
 * Each string found in firmware table buffers is overwritten with spaces.
 * Strings must be in descending length order per category to avoid
 * partial matches interfering with longer matches.
 */

static const char *g_ScrubStrings[] = {
    /* KVM / QEMU / Proxmox */
    "KVMKVMKVM",
    "Proxmox distribution",
    "Proxmox",
    "proxmox",
    "SeaBIOS",
    "BOCHS ",
    "BOCHS",
    "BXPC",
    "QEMU",
    "qemu",

    /* VMware */
    "VMware, Inc.",
    "VMware Virtual Platform",
    "VMware",
    "VMWARE",
    "vmware",

    /* VirtualBox */
    "VirtualBox",
    "VIRTUALBOX",
    "VBOX__",
    "VBOX",
    "innotek GmbH",
    "innotek",
    "Oracle Corporation",
    "Oracle",

    /* Hyper-V */
    "Hyper-V",
    "Microsoft Corporation",
    "Virtual Machine",
    "VIRTUAL",
    "Virtual",

    /* Xen */
    "XenVMM",
    "Xen",
    "xen",

    /* Parallels */
    "Parallels",
    "parallels",
    "prl_",

    /* Generic */
    "Red Hat",
    "VirtIO",
    "virtio",
    "EDK II",

    NULL  /* sentinel */
};

/* ------------------------------------------------------------------ */
/*  Structures and globals                                             */
/* ------------------------------------------------------------------ */

PVOID g_NtosBase = NULL;
PVOID g_NtosEnd = NULL;
PVOID g_ExpFirmwareTableResource = NULL;
PVOID g_ExpFirmwareTableProviderListHead = NULL;

typedef NTSTATUS(__cdecl *PFNFTH)(PSYSTEM_FIRMWARE_TABLE_INFORMATION);

PFNFTH g_OriginalACPIHandler = NULL;
PFNFTH g_OriginalRSMBHandler = NULL;
PFNFTH g_OriginalFIRMHandler = NULL;

typedef struct _SYSTEM_FIRMWARE_TABLE_HANDLER_NODE {
    SYSTEM_FIRMWARE_TABLE_HANDLER SystemFWHandler;
    LIST_ENTRY FirmwareTableProviderList;
} SYSTEM_FIRMWARE_TABLE_HANDLER_NODE, *PSYSTEM_FIRMWARE_TABLE_HANDLER_NODE;

#define EX_FIELD_ADDRESS(Type, Base, Member) \
    ((PUCHAR)Base + FIELD_OFFSET(Type, Member))

#define EX_FOR_EACH_IN_LIST(_Type, _Link, _Head, _Current)              \
    for((_Current) = CONTAINING_RECORD((_Head)->Flink, _Type, _Link);   \
       (_Head) != (PLIST_ENTRY)EX_FIELD_ADDRESS(_Type, _Current, _Link);\
       (_Current) = CONTAINING_RECORD(                                   \
           ((PLIST_ENTRY)EX_FIELD_ADDRESS(_Type, _Current, _Link))->Flink, \
           _Type, _Link))

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    IN ULONG SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

/* ------------------------------------------------------------------ */
/*  Utility functions                                                  */
/* ------------------------------------------------------------------ */

PVOID UtilGetSystemProcAddress(const wchar_t *name)
{
    UNICODE_STRING ustr;
    RtlInitUnicodeString(&ustr, name);
    return MmGetSystemRoutineAddress(&ustr);
}

PVOID UtilMemMem(const void *haystack, SIZE_T haystackLen,
                  const void *needle, SIZE_T needleLen)
{
    if (needleLen > haystackLen) return NULL;
    for (SIZE_T i = 0; i <= haystackLen - needleLen; i++) {
        if (RtlCompareMemory((PUCHAR)haystack + i, needle, needleLen) == needleLen)
            return (PVOID)((PUCHAR)haystack + i);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  String scrubber                                                    */
/* ------------------------------------------------------------------ */

/*
 * Search buffer for all known hypervisor strings and overwrite with spaces.
 * Handles both ASCII and partial matches. Preserves buffer size/layout.
 */
static void ScrubBuffer(PUCHAR buffer, ULONG length)
{
    if (!buffer || length == 0) return;

    for (int s = 0; g_ScrubStrings[s] != NULL; s++) {
        const char *pattern = g_ScrubStrings[s];
        SIZE_T patLen = strlen(pattern);
        if (patLen == 0 || patLen > length) continue;

        for (ULONG i = 0; i <= length - (ULONG)patLen; i++) {
            if (RtlCompareMemory(buffer + i, pattern, patLen) == patLen) {
                /* Overwrite with spaces to preserve offsets */
                for (SIZE_T j = 0; j < patLen; j++) {
                    buffer[i + j] = ' ';
                }
                /* Don't advance past — allow overlapping patterns */
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Firmware table hook handlers                                       */
/* ------------------------------------------------------------------ */

static NTSTATUS __cdecl MyACPIHandler(PSYSTEM_FIRMWARE_TABLE_INFORMATION info)
{
    NTSTATUS status = g_OriginalACPIHandler(info);
    if (NT_SUCCESS(status) && info->TableBufferLength > 0) {
        ScrubBuffer(info->TableBuffer, info->TableBufferLength);
    }
    return status;
}

static NTSTATUS __cdecl MyRSMBHandler(PSYSTEM_FIRMWARE_TABLE_INFORMATION info)
{
    NTSTATUS status = g_OriginalRSMBHandler(info);
    if (NT_SUCCESS(status) && info->TableBufferLength > 0) {
        ScrubBuffer(info->TableBuffer, info->TableBufferLength);
    }
    return status;
}

static NTSTATUS __cdecl MyFIRMHandler(PSYSTEM_FIRMWARE_TABLE_INFORMATION info)
{
    NTSTATUS status = g_OriginalFIRMHandler(info);
    if (NT_SUCCESS(status) && info->TableBufferLength > 0) {
        ScrubBuffer(info->TableBuffer, info->TableBufferLength);
    }
    return status;
}

/* ------------------------------------------------------------------ */
/*  Kernel base discovery                                              */
/* ------------------------------------------------------------------ */

static bool GetKernelBase(PRTL_PROCESS_MODULE_INFORMATION pMod, void *checkPtr)
{
    if (!g_NtosBase) {
        if (pMod->LoadOrderIndex == 0 ||
            (checkPtr >= pMod->ImageBase &&
             checkPtr < (PVOID)((PUCHAR)pMod->ImageBase + pMod->ImageSize))) {
            g_NtosBase = pMod->ImageBase;
            g_NtosEnd = (PUCHAR)pMod->ImageBase + pMod->ImageSize;
            return true;
        }
    }
    return false;
}

static NTSTATUS FindKernelBase()
{
    ULONG cbBuffer = 0;
    PVOID pBuffer = NULL;
    NTSTATUS status;

    while (1) {
        cbBuffer += 0x40000;
        pBuffer = ExAllocatePool2(POOL_FLAG_PAGED, cbBuffer, 'hvhd');
        if (!pBuffer) return STATUS_INSUFFICIENT_RESOURCES;

        status = ZwQuerySystemInformation(0xB /*SystemModuleInformation*/,
                                          pBuffer, cbBuffer, NULL);
        if (NT_SUCCESS(status)) break;

        ExFreePoolWithTag(pBuffer, 'hvhd');
        if (status != STATUS_INFO_LENGTH_MISMATCH)
            return status;
    }

    PVOID checkPtr = UtilGetSystemProcAddress(L"NtOpenFile");
    auto pMods = (PRTL_PROCESS_MODULES)pBuffer;

    for (ULONG i = 0; i < pMods->NumberOfModules; i++) {
        if (GetKernelBase(&pMods->Modules[i], checkPtr))
            break;
    }

    ExFreePoolWithTag(pBuffer, 'hvhd');
    return g_NtosBase ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/* ------------------------------------------------------------------ */
/*  Capstone-based structure locator                                   */
/*                                                                     */
/*  Finds ExpFirmwareTableResource and ExpFirmwareTableProviderListHead*/
/*  by disassembling ntoskrnl's PAGE section, starting from the        */
/*  'mov r8d, TFRA' instruction in the firmware table registration     */
/*  path. Walks forward through branches (up to depth 16) looking for  */
/*  lea rcx,[rip+disp] before ExAcquireResourceSharedLite (= Resource) */
/*  and mov rax,[rip+disp] after it (= ListHead).                     */
/*                                                                     */
/*  This is identical to VmwareHardenedLoader's approach and works     */
/*  across Windows 10/11 versions without hardcoded offsets.           */
/* ------------------------------------------------------------------ */

/* NOTE: The Capstone-based disassembly walker (DisasmRangesWalk) and
 * LocateExpFirmwareTable callback are identical to VmwareHardenedLoader's
 * implementation. Include cs_driver_mm.c/.h from the original project
 * and copy the DisasmRangesWalk + LocateExpFirmwareTable functions
 * verbatim — they are hypervisor-independent.
 *
 * For the initial build, we provide stub declarations here.
 * Replace with the full Capstone implementation from VmwareHardenedLoader.
 */

/* Forward declaration — implement from VmwareHardenedLoader source */
extern bool LocateExpFirmwareTablePointers(PUCHAR PAGEBase, SIZE_T PAGESize);

/* ------------------------------------------------------------------ */
/*  Driver entry / unload                                              */
/* ------------------------------------------------------------------ */

static void DriverUnload(PDRIVER_OBJECT driverObject)
{
    UNREFERENCED_PARAMETER(driverObject);
    PAGED_CODE();

    if (!g_ExpFirmwareTableResource || !g_ExpFirmwareTableProviderListHead)
        return;

    ExAcquireResourceExclusiveLite(
        (PERESOURCE)g_ExpFirmwareTableResource, TRUE);

    PSYSTEM_FIRMWARE_TABLE_HANDLER_NODE node = NULL;

    EX_FOR_EACH_IN_LIST(SYSTEM_FIRMWARE_TABLE_HANDLER_NODE,
        FirmwareTableProviderList,
        (PLIST_ENTRY)g_ExpFirmwareTableProviderListHead,
        node) {

        if (g_OriginalACPIHandler &&
            node->SystemFWHandler.ProviderSignature == 'ACPI') {
            node->SystemFWHandler.FirmwareTableHandler = g_OriginalACPIHandler;
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                       "HypervisorHide: ACPI handler restored\n");
        }
        if (g_OriginalRSMBHandler &&
            node->SystemFWHandler.ProviderSignature == 'RSMB') {
            node->SystemFWHandler.FirmwareTableHandler = g_OriginalRSMBHandler;
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                       "HypervisorHide: RSMB handler restored\n");
        }
        if (g_OriginalFIRMHandler &&
            node->SystemFWHandler.ProviderSignature == 'FIRM') {
            node->SystemFWHandler.FirmwareTableHandler = g_OriginalFIRMHandler;
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                       "HypervisorHide: FIRM handler restored\n");
        }
    }

    ExReleaseResourceLite((PERESOURCE)g_ExpFirmwareTableResource);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);
    PAGED_CODE();

#if HYPERVISORHIDE_STUB_ONLY
    driverObject->DriverUnload = DriverUnload;
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
               "HypervisorHide: STUB MODE — driver loaded, doing nothing\n");
    return STATUS_SUCCESS;
#endif

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
               "HypervisorHide: loading (universal hypervisor firmware scrubber)\n");

    /* 1. Find ntoskrnl base */
    NTSTATUS status = FindKernelBase();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "HypervisorHide: ntoskrnl base not found\n");
        return STATUS_UNSUCCESSFUL;
    }

#if HYPERVISORHIDE_HARDCODED
    /* Hardcoded offsets for Win11 26200 — found via find_firmware_table.py.
     * These are RVAs from ntoskrnl base. */
    g_ExpFirmwareTableResource = (PUCHAR)g_NtosBase + 0xEFEB20;
    g_ExpFirmwareTableProviderListHead = (PUCHAR)g_NtosBase + 0xEFEB98;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
               "HypervisorHide: HARDCODED mode — Resource=%p ListHead=%p\n",
               g_ExpFirmwareTableResource, g_ExpFirmwareTableProviderListHead);
    goto do_hook;
#endif

    /* 2. Find PAGE section */
    auto ntHeader = RtlImageNtHeader(g_NtosBase);
    if (!ntHeader) return STATUS_UNSUCCESSFUL;

    auto secHeader = (PIMAGE_SECTION_HEADER)(
        (PUCHAR)ntHeader + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader)
        + ntHeader->FileHeader.SizeOfOptionalHeader);

    PUCHAR PAGEBase = NULL;
    SIZE_T PAGESize = 0;

    for (USHORT i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        if (memcmp(secHeader[i].Name, "PAGE\x0\x0\x0\x0", 8) == 0) {
            PAGEBase = (PUCHAR)g_NtosBase + secHeader[i].VirtualAddress;
            PAGESize = max(secHeader[i].SizeOfRawData,
                          secHeader[i].Misc.VirtualSize);
            break;
        }
    }

    if (!PAGEBase) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "HypervisorHide: PAGE section not found\n");
        return STATUS_UNSUCCESSFUL;
    }

    /* 3. Locate ExpFirmwareTable* via pattern + disassembly        */
    /*    Pattern: mov r8d, 'TFRA' = 41 B8 41 52 46 54            */
    /*    Multiple matches exist — iterate all until one succeeds. */
    cs_driver_mm_init();

    PUCHAR searchBase = PAGEBase;
    SIZE_T searchLen = PAGESize;
    bool found = false;
    int matchCount = 0;

    while (searchLen > 6) {
        auto findMovTag = UtilMemMem(searchBase, searchLen,
                                      "\x41\xB8\x41\x52\x46\x54", 6);
        if (!findMovTag) break;

        matchCount++;
        PUCHAR matchAddr = (PUCHAR)findMovTag;

        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                   "HypervisorHide: trying pattern match %d at %p\n",
                   matchCount, matchAddr);

        if (LocateExpFirmwareTablePointers(matchAddr + 6, 0x400)) {
            found = true;
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                       "HypervisorHide: found structures at match %d\n",
                       matchCount);
            break;
        }

        /* Advance past this match */
        SIZE_T consumed = (SIZE_T)(matchAddr + 6 - searchBase);
        searchBase = matchAddr + 6;
        searchLen -= consumed;
    }

    if (!found) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "HypervisorHide: firmware table structures not found "
                   "(%d pattern matches tried)\n", matchCount);
#if HYPERVISORHIDE_DEBUG_ONLY
        /* In debug mode, succeed anyway so we stay loaded for diagnostics */
        driverObject->DriverUnload = DriverUnload;
        return STATUS_SUCCESS;
#else
        return STATUS_UNSUCCESSFUL;
#endif
    }

do_hook:
    /* 4. Validate the pointers before using them */
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
               "HypervisorHide: Resource=%p ListHead=%p\n",
               g_ExpFirmwareTableResource, g_ExpFirmwareTableProviderListHead);

    /* Sanity check: both must be in kernel data section */
    if (g_ExpFirmwareTableResource < g_NtosBase ||
        g_ExpFirmwareTableResource >= g_NtosEnd ||
        g_ExpFirmwareTableProviderListHead < g_NtosBase ||
        g_ExpFirmwareTableProviderListHead >= g_NtosEnd) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "HypervisorHide: pointers outside ntoskrnl range — aborting\n");
        return STATUS_UNSUCCESSFUL;
    }

#if HYPERVISORHIDE_DEBUG_ONLY
    /* Debug mode: log what we found but don't touch anything.
     * Check DebugView or WinDbg for output. */
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
               "HypervisorHide: DEBUG MODE — not hooking. "
               "Resource=%p ListHead=%p. "
               "Set HYPERVISORHIDE_DEBUG_ONLY=0 and rebuild to enable hooking.\n",
               g_ExpFirmwareTableResource, g_ExpFirmwareTableProviderListHead);

    /* Try to read the list head to verify it's a valid LIST_ENTRY */
    __try {
        PLIST_ENTRY listHead = (PLIST_ENTRY)g_ExpFirmwareTableProviderListHead;
        PLIST_ENTRY flink = listHead->Flink;
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "HypervisorHide: ListHead->Flink=%p (valid read)\n", flink);

        /* Walk the list and log provider signatures */
        PLIST_ENTRY current = flink;
        int count = 0;
        while (current != listHead && count < 20) {
            PSYSTEM_FIRMWARE_TABLE_HANDLER_NODE node =
                CONTAINING_RECORD(current, SYSTEM_FIRMWARE_TABLE_HANDLER_NODE,
                                  FirmwareTableProviderList);
            char sig[5] = {};
            *(ULONG*)sig = node->SystemFWHandler.ProviderSignature;
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                       "HypervisorHide: Provider '%s' handler=%p\n",
                       sig, node->SystemFWHandler.FirmwareTableHandler);
            current = current->Flink;
            count++;
        }
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "HypervisorHide: %d providers found\n", count);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "HypervisorHide: EXCEPTION reading list — pointers are WRONG\n");
    }

    driverObject->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;

#else
    /* Production mode: hook the providers */
    ExAcquireResourceExclusiveLite(
        (PERESOURCE)g_ExpFirmwareTableResource, TRUE);

    PSYSTEM_FIRMWARE_TABLE_HANDLER_NODE node = NULL;

    EX_FOR_EACH_IN_LIST(SYSTEM_FIRMWARE_TABLE_HANDLER_NODE,
        FirmwareTableProviderList,
        (PLIST_ENTRY)g_ExpFirmwareTableProviderListHead,
        node) {

        if (!g_OriginalACPIHandler &&
            node->SystemFWHandler.ProviderSignature == 'ACPI') {
            g_OriginalACPIHandler = node->SystemFWHandler.FirmwareTableHandler;
            node->SystemFWHandler.FirmwareTableHandler = MyACPIHandler;
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                       "HypervisorHide: ACPI handler hooked\n");
        }
        if (!g_OriginalRSMBHandler &&
            node->SystemFWHandler.ProviderSignature == 'RSMB') {
            g_OriginalRSMBHandler = node->SystemFWHandler.FirmwareTableHandler;
            node->SystemFWHandler.FirmwareTableHandler = MyRSMBHandler;
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                       "HypervisorHide: RSMB handler hooked\n");
        }
        if (!g_OriginalFIRMHandler &&
            node->SystemFWHandler.ProviderSignature == 'FIRM') {
            g_OriginalFIRMHandler = node->SystemFWHandler.FirmwareTableHandler;
            node->SystemFWHandler.FirmwareTableHandler = MyFIRMHandler;
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                       "HypervisorHide: FIRM handler hooked\n");
        }
    }

    ExReleaseResourceLite((PERESOURCE)g_ExpFirmwareTableResource);

    driverObject->DriverUnload = DriverUnload;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
               "HypervisorHide: loaded successfully — all firmware table providers hooked\n");

    return STATUS_SUCCESS;
#endif
}

} /* extern "C" */
