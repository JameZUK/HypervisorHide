/*
 * Capstone kernel-mode memory allocator.
 * Provides malloc/calloc/realloc/free/vsnprintf for Capstone in kernel mode.
 *
 * From VmwareHardenedLoader (hzqst) — unchanged, hypervisor-independent.
 */

#include <ntddk.h>
#include <capstone/capstone.h>

#define CS_POOL_TAG 'cshv'

static void * __cdecl cs_km_malloc(size_t size)
{
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, CS_POOL_TAG);
}

static void * __cdecl cs_km_calloc(size_t count, size_t size)
{
    size_t total = count * size;
    void *p = ExAllocatePool2(POOL_FLAG_NON_PAGED, total, CS_POOL_TAG);
    if (p) RtlZeroMemory(p, total);
    return p;
}

static void * __cdecl cs_km_realloc(void *ptr, size_t size)
{
    void *newp = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, CS_POOL_TAG);
    if (newp && ptr) {
        /* Can't know original size; copy up to new size (safe for grow) */
        RtlCopyMemory(newp, ptr, size);
        ExFreePoolWithTag(ptr, CS_POOL_TAG);
    }
    return newp;
}

static void __cdecl cs_km_free(void *ptr)
{
    if (ptr) ExFreePoolWithTag(ptr, CS_POOL_TAG);
}

static int __cdecl cs_km_vsnprintf(char *buffer, size_t count,
                                    const char *format, va_list argptr)
{
    return _vsnprintf(buffer, count, format, argptr);
}

void cs_driver_mm_init(void)
{
    cs_opt_mem mem = {
        .malloc  = cs_km_malloc,
        .calloc  = cs_km_calloc,
        .realloc = cs_km_realloc,
        .free    = cs_km_free,
        .vsnprintf = cs_km_vsnprintf,
    };
    cs_option(0, CS_OPT_MEM, (size_t)&mem);
}
