/*
 * Capstone kernel-mode memory allocator header.
 * Required for using Capstone disassembly in a Windows kernel driver.
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void cs_driver_mm_init(void);

#ifdef __cplusplus
}
#endif
