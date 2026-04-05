/*
 * Capstone 5.x kernel-mode support.
 * Provides memory allocators and printf stubs for kernel drivers.
 */

#include <ntddk.h>

#define CS_POOL_TAG 'cshv'

/* Capstone 5.x expects these specific function names for kernel mode */
void *cs_winkernel_malloc(size_t size)
{
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, CS_POOL_TAG);
}

void *cs_winkernel_calloc(size_t count, size_t size)
{
    size_t total = count * size;
    void *p = ExAllocatePool2(POOL_FLAG_NON_PAGED, total, CS_POOL_TAG);
    /* ExAllocatePool2 already zeroes memory */
    return p;
}

void *cs_winkernel_realloc(void *ptr, size_t size)
{
    void *newp = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, CS_POOL_TAG);
    if (newp && ptr) {
        RtlCopyMemory(newp, ptr, size);
        ExFreePoolWithTag(ptr, CS_POOL_TAG);
    }
    return newp;
}

void cs_winkernel_free(void *ptr)
{
    if (ptr) ExFreePoolWithTag(ptr, CS_POOL_TAG);
}

int cs_winkernel_vsnprintf(char *buffer, size_t count,
                            const char *format, va_list argptr)
{
    /* Use ntoskrnl's _vsnprintf */
    return _vsnprintf(buffer, count, format, argptr);
}

/* Stub for __stdio_common_vsprintf (used by UCRT _vsnprintf) */
int __cdecl __stdio_common_vsprintf(
    unsigned __int64 options, char *buffer, size_t count,
    const char *format, void *locale, va_list argptr)
{
    (void)options;
    (void)locale;
    return _vsnprintf(buffer, count, format, argptr);
}

/* Stubs for printf/fprintf (Capstone Mapping.c references these even in DIET mode) */
void *__cdecl __acrt_iob_func(unsigned int index) { (void)index; return (void*)0; }
int __cdecl __stdio_common_vfprintf(unsigned __int64 o, void *s, const char *f, void *l, va_list a)
    { (void)o; (void)s; (void)f; (void)l; (void)a; return 0; }
/* printf is defined in Capstone's Mapping.c — don't duplicate */

void cs_driver_mm_init(void)
{
    /* Capstone 5.x auto-detects kernel mode and uses cs_winkernel_* functions.
     * No explicit cs_option(CS_OPT_MEM) call needed. */
}
