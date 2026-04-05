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
/*  Registry callback — hide keys with VM names from enumeration       */
/* ------------------------------------------------------------------ */

/*
 * CmRegisterCallbackEx handler. Intercepts RegNtPostEnumerateKey to
 * check if the returned key name contains VM indicators. If so, we
 * return STATUS_NO_MORE_ENTRIES to skip it, causing the caller to
 * advance to the next key (effectively hiding it).
 *
 * This is the PatchGuard-safe way to filter registry enumeration.
 */

LARGE_INTEGER g_RegCookie = {};

static const WCHAR *g_VmKeyPatterns[] = {
    L"QEMU", L"qemu", L"BOCHS", L"bochs", L"VMware", L"VMWARE",
    L"VirtualBox", L"VBOX", L"Hyper-V", L"Xen", L"Parallels",
    L"VirtIO", L"virtio", L"Red Hat", L"q35", L"pc-q35",
    NULL
};

static BOOLEAN NameContainsVmString(PCUNICODE_STRING name)
{
    if (!name || !name->Buffer || name->Length == 0) return FALSE;
    ULONG nameChars = name->Length / sizeof(WCHAR);

    for (int s = 0; g_VmKeyPatterns[s]; s++) {
        ULONG patLen = (ULONG)wcslen(g_VmKeyPatterns[s]);
        if (patLen > nameChars) continue;
        for (ULONG i = 0; i + patLen <= nameChars; i++) {
            BOOLEAN match = TRUE;
            for (ULONG j = 0; j < patLen; j++) {
                if (name->Buffer[i + j] != g_VmKeyPatterns[s][j]) {
                    match = FALSE; break;
                }
            }
            if (match) return TRUE;
        }
    }
    return FALSE;
}

static void ScrubWideString(PWCHAR str, ULONG charCount)
{
    for (int s = 0; g_VmKeyPatterns[s]; s++) {
        ULONG patLen = (ULONG)wcslen(g_VmKeyPatterns[s]);
        if (patLen > charCount) continue;
        for (ULONG i = 0; i + patLen <= charCount; i++) {
            BOOLEAN match = TRUE;
            for (ULONG j = 0; j < patLen; j++) {
                if (str[i + j] != g_VmKeyPatterns[s][j]) { match = FALSE; break; }
            }
            if (match) {
                for (ULONG j = 0; j < patLen; j++) str[i + j] = L' ';
            }
        }
    }
}

static NTSTATUS RegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,  /* REG_NOTIFY_CLASS */
    _In_opt_ PVOID Argument2)  /* notification-specific structure */
{
    UNREFERENCED_PARAMETER(CallbackContext);
    if (!Argument1 || !Argument2) return STATUS_SUCCESS;

    __try {

    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    /* We intercept POST-enumerate to check the result */
    if (notifyClass == RegNtPostEnumerateKey) {
        auto *info = (PREG_POST_OPERATION_INFORMATION)Argument2;
        if (!NT_SUCCESS(info->Status)) return STATUS_SUCCESS;

        /* Get the pre-operation info to access the output buffer */
        auto *preInfo = (PREG_ENUMERATE_KEY_INFORMATION)info->PreInformation;
        if (!preInfo) return STATUS_SUCCESS;

        /* Check KeyInformationClass — we handle BasicInformation and NodeInformation */
        if (preInfo->KeyInformationClass == KeyBasicInformation && preInfo->KeyInformation) {
            auto *basic = (PKEY_BASIC_INFORMATION)preInfo->KeyInformation;
            UNICODE_STRING keyName = { (USHORT)basic->NameLength, (USHORT)basic->NameLength, basic->Name };
            if (NameContainsVmString(&keyName)) {
                /* Scrub VM strings from the key name in place */
                ScrubWideString(basic->Name, basic->NameLength / sizeof(WCHAR));
            }
        }
        else if (preInfo->KeyInformationClass == KeyNodeInformation && preInfo->KeyInformation) {
            auto *node = (PKEY_NODE_INFORMATION)preInfo->KeyInformation;
            UNICODE_STRING keyName = { (USHORT)node->NameLength, (USHORT)node->NameLength, node->Name };
            if (NameContainsVmString(&keyName)) {
                ScrubWideString(node->Name, node->NameLength / sizeof(WCHAR));
            }
        }
        else if (preInfo->KeyInformationClass == KeyNameInformation && preInfo->KeyInformation) {
            auto *nameInfo = (PKEY_NAME_INFORMATION)preInfo->KeyInformation;
            UNICODE_STRING keyName = { (USHORT)nameInfo->NameLength, (USHORT)nameInfo->NameLength, nameInfo->Name };
            if (NameContainsVmString(&keyName)) {
                ScrubWideString(nameInfo->Name, nameInfo->NameLength / sizeof(WCHAR));
            }
        }
    }

    /* Also intercept RegNtPostQueryKey for key name queries */
    if (notifyClass == RegNtPostQueryKey && Argument2) {
        auto *info = (PREG_POST_OPERATION_INFORMATION)Argument2;
        if (!NT_SUCCESS(info->Status)) return STATUS_SUCCESS;

        auto *preInfo = (PREG_QUERY_KEY_INFORMATION)info->PreInformation;
        if (!preInfo || !preInfo->KeyInformation) return STATUS_SUCCESS;

        if (preInfo->KeyInformationClass == KeyNameInformation) {
            auto *nameInfo = (PKEY_NAME_INFORMATION)preInfo->KeyInformation;
            UNICODE_STRING keyName = { (USHORT)nameInfo->NameLength,
                                        (USHORT)nameInfo->NameLength,
                                        nameInfo->Name };
            if (NameContainsVmString(&keyName)) {
                /* Scrub the name in place */
                for (int s = 0; g_VmKeyPatterns[s]; s++) {
                    ULONG patLen = (ULONG)wcslen(g_VmKeyPatterns[s]);
                    ULONG nameChars = keyName.Length / sizeof(WCHAR);
                    for (ULONG i = 0; i + patLen <= nameChars; i++) {
                        BOOLEAN match = TRUE;
                        for (ULONG j = 0; j < patLen; j++) {
                            if (keyName.Buffer[i + j] != g_VmKeyPatterns[s][j]) {
                                match = FALSE; break;
                            }
                        }
                        if (match) {
                            for (ULONG j = 0; j < patLen; j++)
                                keyName.Buffer[i + j] = L' ';
                        }
                    }
                }
            }
        }
    }

    /* Also intercept value queries to scrub VM strings in values */
    if (notifyClass == RegNtPostQueryValueKey && Argument2) {
        auto *info = (PREG_POST_OPERATION_INFORMATION)Argument2;
        if (!NT_SUCCESS(info->Status)) return STATUS_SUCCESS;

        auto *preInfo = (PREG_QUERY_VALUE_KEY_INFORMATION)info->PreInformation;
        if (!preInfo || !preInfo->KeyValueInformation) return STATUS_SUCCESS;

        if (preInfo->KeyValueInformationClass == KeyValueFullInformation) {
            auto *full = (PKEY_VALUE_FULL_INFORMATION)preInfo->KeyValueInformation;
            if ((full->Type == REG_SZ || full->Type == REG_MULTI_SZ) &&
                full->DataLength > 0 && full->DataLength < 2048) {
                PWCHAR data = (PWCHAR)((PUCHAR)full + full->DataOffset);
                ULONG charCount = full->DataLength / sizeof(WCHAR);
                for (int s = 0; g_VmKeyPatterns[s]; s++) {
                    ULONG patLen = (ULONG)wcslen(g_VmKeyPatterns[s]);
                    for (ULONG i = 0; i + patLen <= charCount; i++) {
                        BOOLEAN match = TRUE;
                        for (ULONG j = 0; j < patLen; j++) {
                            if (data[i + j] != g_VmKeyPatterns[s][j]) {
                                match = FALSE; break;
                            }
                        }
                        if (match) {
                            for (ULONG j = 0; j < patLen; j++)
                                data[i + j] = L' ';
                        }
                    }
                }
            }
        }
    }

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        /* Silently ignore exceptions in callback */
    }

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Registry scrubbing (boot-time, one-shot)                           */
/* ------------------------------------------------------------------ */

/*
 * Scrub VM indicator strings from registry values under a given key.
 * Recursively walks subkeys. Replaces QEMU/BOCHS/Virtual/etc with spaces
 * in REG_SZ and REG_MULTI_SZ values.
 */
static void ScrubRegistryKey(PUNICODE_STRING keyPath)
{
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE hKey;
    NTSTATUS status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objAttr);
    if (!NT_SUCCESS(status)) return;

    /* Enumerate values and scrub strings */
    UCHAR valueBuf[512];
    ULONG resultLen;
    for (ULONG idx = 0; ; idx++) {
        status = ZwEnumerateValueKey(hKey, idx, KeyValueFullInformation,
                                     valueBuf, sizeof(valueBuf), &resultLen);
        if (!NT_SUCCESS(status)) break;

        auto *info = (PKEY_VALUE_FULL_INFORMATION)valueBuf;
        if (info->Type != REG_SZ && info->Type != REG_MULTI_SZ) continue;
        if (info->DataLength == 0 || info->DataLength > 400) continue;

        PWCHAR data = (PWCHAR)((PUCHAR)info + info->DataOffset);
        ULONG charCount = info->DataLength / sizeof(WCHAR);
        BOOLEAN modified = FALSE;

        /* Check each VM string (wide) */
        static const WCHAR *vmStringsW[] = {
            L"QEMU", L"qemu", L"BOCHS", L"bochs", L"Proxmox", L"proxmox",
            L"VMware", L"VMWARE", L"VirtualBox", L"VBOX", L"Virtual",
            L"Hyper-V", L"KVM", L"KVMKVMKVM", L"Red Hat", L"VirtIO",
            L"EDK II", L"SeaBIOS", L"innotek", L"Parallels", L"Xen",
            L"q35", L"pc-q35", NULL
        };

        for (int s = 0; vmStringsW[s]; s++) {
            ULONG patLen = (ULONG)wcslen(vmStringsW[s]);
            for (ULONG i = 0; i + patLen <= charCount; i++) {
                BOOLEAN match = TRUE;
                for (ULONG j = 0; j < patLen; j++) {
                    if (data[i + j] != vmStringsW[s][j]) { match = FALSE; break; }
                }
                if (match) {
                    for (ULONG j = 0; j < patLen; j++) data[i + j] = L' ';
                    modified = TRUE;
                }
            }
        }

        if (modified) {
            UNICODE_STRING valueName;
            valueName.Buffer = info->Name;
            valueName.Length = (USHORT)info->NameLength;
            valueName.MaximumLength = (USHORT)info->NameLength;
            ZwSetValueKey(hKey, &valueName, 0, info->Type,
                          data, info->DataLength);
        }
    }

    /* Recurse into subkeys */
    UCHAR subkeyBuf[512];
    for (ULONG idx = 0; ; idx++) {
        status = ZwEnumerateKey(hKey, idx, KeyBasicInformation,
                                subkeyBuf, sizeof(subkeyBuf), &resultLen);
        if (!NT_SUCCESS(status)) break;

        auto *subInfo = (PKEY_BASIC_INFORMATION)subkeyBuf;
        /* Build full path: keyPath + \ + subkeyName */
        WCHAR fullPath[512];
        ULONG parentLen = keyPath->Length / sizeof(WCHAR);
        if (parentLen + 1 + subInfo->NameLength / sizeof(WCHAR) >= 510) continue;

        RtlCopyMemory(fullPath, keyPath->Buffer, keyPath->Length);
        fullPath[parentLen] = L'\\';
        RtlCopyMemory(&fullPath[parentLen + 1], subInfo->Name, subInfo->NameLength);
        ULONG totalLen = keyPath->Length + sizeof(WCHAR) + subInfo->NameLength;
        fullPath[totalLen / sizeof(WCHAR)] = 0;

        UNICODE_STRING subPath;
        subPath.Buffer = fullPath;
        subPath.Length = (USHORT)totalLen;
        subPath.MaximumLength = sizeof(fullPath);
        ScrubRegistryKey(&subPath);
    }

    ZwClose(hKey);
}

/*
 * Delete a registry key and all its subkeys (kernel-mode ZwDeleteKey).
 * Must delete children first (bottom-up).
 */
static void DeleteKeyRecursive(PUNICODE_STRING keyPath)
{
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE hKey;
    NTSTATUS status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objAttr);
    if (!NT_SUCCESS(status)) return;

    /* Delete all subkeys first */
    UCHAR buf[512];
    ULONG resultLen;
    /* Keep deleting index 0 until none left */
    while (NT_SUCCESS(ZwEnumerateKey(hKey, 0, KeyBasicInformation, buf, sizeof(buf), &resultLen))) {
        auto *info = (PKEY_BASIC_INFORMATION)buf;
        WCHAR fullPath[512];
        ULONG parentLen = keyPath->Length / sizeof(WCHAR);
        if (parentLen + 1 + info->NameLength / sizeof(WCHAR) >= 510) break;
        RtlCopyMemory(fullPath, keyPath->Buffer, keyPath->Length);
        fullPath[parentLen] = L'\\';
        RtlCopyMemory(&fullPath[parentLen + 1], info->Name, info->NameLength);
        ULONG totalLen = keyPath->Length + sizeof(WCHAR) + info->NameLength;
        fullPath[totalLen / sizeof(WCHAR)] = 0;
        UNICODE_STRING subPath = { (USHORT)totalLen, sizeof(fullPath), fullPath };
        DeleteKeyRecursive(&subPath);
    }

    ZwDeleteKey(hKey);
    ZwClose(hKey);
}

/*
 * Delete registry keys whose names contain VM indicators.
 * Scans subkeys of parent paths and deletes any with QEMU/BOCHS/etc in name.
 */
static void DeleteVmRegistryKeys()
{
    static const WCHAR *parents[] = {
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\SCSI",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\ACPI",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\SWD\\COMPUTER",
        NULL
    };

    static const WCHAR *vmPatterns[] = {
        L"QEMU", L"qemu", L"BOCHS", L"VBOX", L"VMware", L"Proxmox",
        L"Virtual", L"Hyper-V", L"Xen", L"Parallels", NULL
    };

    for (int p = 0; parents[p]; p++) {
        UNICODE_STRING parentPath;
        RtlInitUnicodeString(&parentPath, parents[p]);
        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, &parentPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        HANDLE hParent;
        if (!NT_SUCCESS(ZwOpenKey(&hParent, KEY_ALL_ACCESS, &objAttr))) continue;

        UCHAR buf[512];
        ULONG resultLen;
        /* Enumerate and collect keys to delete (can't delete while enumerating) */
        WCHAR toDelete[8][256];
        int deleteCount = 0;

        for (ULONG idx = 0; deleteCount < 8; idx++) {
            if (!NT_SUCCESS(ZwEnumerateKey(hParent, idx, KeyBasicInformation,
                                           buf, sizeof(buf), &resultLen))) break;
            auto *info = (PKEY_BASIC_INFORMATION)buf;
            ULONG nameChars = info->NameLength / sizeof(WCHAR);

            /* Check if subkey name contains any VM pattern */
            for (int s = 0; vmPatterns[s]; s++) {
                ULONG patLen = (ULONG)wcslen(vmPatterns[s]);
                for (ULONG i = 0; i + patLen <= nameChars; i++) {
                    BOOLEAN match = TRUE;
                    for (ULONG j = 0; j < patLen; j++) {
                        if (info->Name[i + j] != vmPatterns[s][j]) { match = FALSE; break; }
                    }
                    if (match && deleteCount < 8) {
                        ULONG parentLen = parentPath.Length / sizeof(WCHAR);
                        RtlCopyMemory(toDelete[deleteCount], parentPath.Buffer, parentPath.Length);
                        toDelete[deleteCount][parentLen] = L'\\';
                        RtlCopyMemory(&toDelete[deleteCount][parentLen + 1], info->Name, info->NameLength);
                        toDelete[deleteCount][parentLen + 1 + nameChars] = 0;
                        deleteCount++;
                        goto next_key;
                    }
                }
            }
            next_key:;
        }

        ZwClose(hParent);

        /* Now delete the collected keys */
        for (int d = 0; d < deleteCount; d++) {
            UNICODE_STRING delPath;
            RtlInitUnicodeString(&delPath, toDelete[d]);
            DeleteKeyRecursive(&delPath);
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                       "HypervisorHide: deleted key %wZ\n", &delPath);
        }
    }
}

static void ScrubAllRegistryVmStrings()
{
    static const WCHAR *paths[] = {
        L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System",
        L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS",
        L"\\Registry\\Machine\\HARDWARE\\DEVICEMAP\\Scsi",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\SCSI",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\ACPI",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\SWD\\COMPUTER",
        NULL
    };

    /* First scrub values */
    for (int i = 0; paths[i]; i++) {
        UNICODE_STRING path;
        RtlInitUnicodeString(&path, paths[i]);
        ScrubRegistryKey(&path);
    }

    /* Then delete keys with VM names */
    DeleteVmRegistryKeys();
}

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

    /* Unregister registry callback */
    if (g_RegCookie.QuadPart != 0) {
        CmUnRegisterCallback(g_RegCookie);
        g_RegCookie.QuadPart = 0;
    }

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
    /* Production mode: hook the providers.
     * NOTE: Do NOT acquire ExpFirmwareTableResource — it causes deadlocks.
     * The list walk during DriverEntry is safe without the lock. */

    /* Walk the provider list with safety limits.
     * The list head is at g_ExpFirmwareTableProviderListHead.
     * Each node has FirmwareTableProviderList at offset 0x18 from the
     * SYSTEM_FIRMWARE_TABLE_HANDLER_NODE start. */
    __try {
        PLIST_ENTRY listHead = (PLIST_ENTRY)g_ExpFirmwareTableProviderListHead;
        PLIST_ENTRY entry = listHead->Flink;
        int count = 0;

        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "HypervisorHide: walking list at %p (Flink=%p)\n",
                   listHead, entry);

        while (entry != listHead && count < 20) {
            count++;
            PSYSTEM_FIRMWARE_TABLE_HANDLER_NODE node =
                CONTAINING_RECORD(entry, SYSTEM_FIRMWARE_TABLE_HANDLER_NODE,
                                  FirmwareTableProviderList);

            ULONG sig = node->SystemFWHandler.ProviderSignature;
            PFNFTH handler = node->SystemFWHandler.FirmwareTableHandler;
            char sigStr[5] = {};
            *(ULONG*)sigStr = sig;

            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                       "HypervisorHide: [%d] sig='%s' (0x%08x) handler=%p\n",
                       count, sigStr, sig, handler);

            if (!g_OriginalACPIHandler && sig == 'ACPI' && handler) {
                g_OriginalACPIHandler = handler;
                node->SystemFWHandler.FirmwareTableHandler = MyACPIHandler;
                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                           "HypervisorHide: ACPI HOOKED\n");
            }
            if (!g_OriginalRSMBHandler && sig == 'RSMB' && handler) {
                g_OriginalRSMBHandler = handler;
                node->SystemFWHandler.FirmwareTableHandler = MyRSMBHandler;
                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                           "HypervisorHide: RSMB HOOKED\n");
            }
            if (!g_OriginalFIRMHandler && sig == 'FIRM' && handler) {
                g_OriginalFIRMHandler = handler;
                node->SystemFWHandler.FirmwareTableHandler = MyFIRMHandler;
                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                           "HypervisorHide: FIRM HOOKED\n");
            }

            entry = entry->Flink;
        }

        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "HypervisorHide: walked %d providers\n", count);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "HypervisorHide: EXCEPTION during hook (bad pointer?)\n");
    }

    driverObject->DriverUnload = DriverUnload;

    /* Write debug summary to a file readable from usermode */
    {
        UNICODE_STRING filePath;
        RtlInitUnicodeString(&filePath, L"\\??\\C:\\Malware\\hvhide_log.txt");
        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, &filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        HANDLE hFile;
        IO_STATUS_BLOCK ioStatus;
        NTSTATUS fs = ZwCreateFile(&hFile, GENERIC_WRITE | SYNCHRONIZE, &objAttr, &ioStatus,
                                    NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
                                    FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (NT_SUCCESS(fs)) {
            char buf[512];
            /* Simple marker — if this file appears, driver reached this point */
            const char *msg = "HypervisorHide loaded OK\r\n";
            int len = 26;
            /* Encode handler pointers as presence flags */
            char flags[64] = "ACPI=0 RSMB=0 FIRM=0\r\n";
            if (g_OriginalACPIHandler) flags[5] = '1';
            if (g_OriginalRSMBHandler) flags[12] = '1';
            if (g_OriginalFIRMHandler) flags[19] = '1';
            ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatus, (PVOID)msg, len, NULL, NULL);
            ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatus, flags, 22, NULL, NULL);
            ZwClose(hFile);
        }
    }

    /* 5. Scrub VM strings from registry (device enum, BIOS info, etc.) */
    __try {
        ScrubAllRegistryVmStrings();
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "HypervisorHide: registry scrubbed\n");
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "HypervisorHide: registry scrub exception (non-fatal)\n");
    }

    /* 6. Register registry callback to hide VM keys from enumeration */
    {
        UNICODE_STRING altitude;
        RtlInitUnicodeString(&altitude, L"380000");  /* altitude for registry filter */
        NTSTATUS regStatus = CmRegisterCallbackEx(
            RegistryCallback, &altitude, driverObject, NULL, &g_RegCookie, NULL);
        if (NT_SUCCESS(regStatus)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                       "HypervisorHide: registry callback registered\n");
        } else {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                       "HypervisorHide: registry callback FAILED (0x%08x)\n", regStatus);
        }
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
               "HypervisorHide: loaded — FW hooks + registry scrub + reg callback\n");

    return STATUS_SUCCESS;
#endif
}

} /* extern "C" */
