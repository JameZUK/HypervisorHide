/*
 * Locate ExpFirmwareTableResource and ExpFirmwareTableProviderListHead
 * by disassembling ntoskrnl's PAGE section using Capstone.
 *
 * Adapted from VmwareHardenedLoader (hzqst). The technique is:
 *
 * 1. Start disassembling from the 'mov r8d, TFRA' instruction
 *    (inside NtQuerySystemInformation's firmware table path)
 *
 * 2. Walk forward through instructions, following branches up to
 *    depth 16 and max 1000 instructions
 *
 * 3. Look for:
 *    - lea rcx, [rip+disp] BEFORE call ExAcquireResourceSharedLite
 *      → the [rip+disp] target = ExpFirmwareTableResource
 *    - mov rax/rcx, [rip+disp] AFTER that call
 *      → the [rip+disp] target = ExpFirmwareTableProviderListHead
 *
 * This works across Windows 10/11 versions without hardcoded offsets.
 */

#include <fltkernel.h>
#include <capstone/capstone.h>
#include "cs_driver_mm.h"

extern "C" {

extern PVOID g_NtosBase;
extern PVOID g_NtosEnd;
extern PVOID g_ExpFirmwareTableResource;
extern PVOID g_ExpFirmwareTableProviderListHead;

PVOID UtilGetSystemProcAddress(const wchar_t *name);

/*
 * Disassemble a range of code, calling back for each instruction.
 * Follows near jumps/calls up to max_depth.
 * Returns true if the callback signalled completion.
 */
struct DisasmContext {
    PUCHAR base;
    SIZE_T maxLen;
    int maxDepth;
    int maxInsts;
    int instCount;
    PVOID pfn_ExAcquireResourceSharedLite;
    PUCHAR lea_rcx_addr;     /* address of the lea rcx instruction */
    PVOID  lea_rcx_imm;      /* resolved [rip+disp] target */
    int    call_acquire_inst; /* instruction index of the call */
    bool   found;
};

static bool DisasmWalk(csh handle, PUCHAR code, SIZE_T codeLen,
                        uint64_t address, struct DisasmContext *ctx, int depth)
{
    if (depth > ctx->maxDepth) return false;

    cs_insn *insn;
    size_t count = cs_disasm(handle, code, codeLen, address, 0, &insn);
    if (count == 0) return false;

    bool result = false;

    for (size_t i = 0; i < count && ctx->instCount < ctx->maxInsts; i++) {
        ctx->instCount++;
        cs_x86 *x86 = &insn[i].detail->x86;

        /* Track lea rcx, [rip+disp] — candidate for ExpFirmwareTableResource */
        if (insn[i].id == X86_INS_LEA &&
            x86->op_count == 2 &&
            x86->operands[0].type == X86_OP_REG &&
            x86->operands[0].reg == X86_REG_RCX &&
            x86->operands[1].type == X86_OP_MEM &&
            x86->operands[1].mem.base == X86_REG_RIP) {

            ctx->lea_rcx_addr = (PUCHAR)insn[i].address;
            ctx->lea_rcx_imm = (PVOID)(insn[i].address + insn[i].size +
                                       x86->operands[1].mem.disp);
        }

        /* Track call to ExAcquireResourceSharedLite */
        if (insn[i].id == X86_INS_CALL &&
            x86->op_count == 1 &&
            x86->operands[0].type == X86_OP_IMM) {

            PVOID callTarget = (PVOID)x86->operands[0].imm;
            if (callTarget == ctx->pfn_ExAcquireResourceSharedLite) {
                /* The most recent lea rcx is ExpFirmwareTableResource */
                if (ctx->lea_rcx_imm &&
                    ctx->lea_rcx_imm >= g_NtosBase &&
                    ctx->lea_rcx_imm < g_NtosEnd) {

                    g_ExpFirmwareTableResource = ctx->lea_rcx_imm;
                    ctx->call_acquire_inst = ctx->instCount;

                    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                               "HypervisorHide: ExpFirmwareTableResource at %p\n",
                               g_ExpFirmwareTableResource);
                }
            }
        }

        /* After call to ExAcquireResourceSharedLite, look for
         * mov rax/rcx, [rip+disp] → ExpFirmwareTableProviderListHead */
        if (ctx->call_acquire_inst > 0 &&
            ctx->instCount - ctx->call_acquire_inst <= 5 &&
            (insn[i].id == X86_INS_MOV || insn[i].id == X86_INS_LEA) &&
            x86->op_count == 2 &&
            x86->operands[0].type == X86_OP_REG &&
            (x86->operands[0].reg == X86_REG_RAX ||
             x86->operands[0].reg == X86_REG_RCX) &&
            x86->operands[1].type == X86_OP_MEM &&
            x86->operands[1].mem.base == X86_REG_RIP) {

            PVOID target = (PVOID)(insn[i].address + insn[i].size +
                                   x86->operands[1].mem.disp);
            if (target >= g_NtosBase && target < g_NtosEnd) {
                g_ExpFirmwareTableProviderListHead = target;
                ctx->found = true;

                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                           "HypervisorHide: ExpFirmwareTableProviderListHead at %p\n",
                           g_ExpFirmwareTableProviderListHead);

                result = true;
                break;
            }
        }

        /* Follow near jumps/calls to continue tracing */
        if ((insn[i].id == X86_INS_JMP || insn[i].id == X86_INS_CALL) &&
            x86->op_count == 1 &&
            x86->operands[0].type == X86_OP_IMM &&
            !ctx->found) {

            uint64_t target = x86->operands[0].imm;
            if (target >= (uint64_t)g_NtosBase &&
                target < (uint64_t)g_NtosEnd) {

                PUCHAR targetCode = (PUCHAR)target;
                SIZE_T remaining = (SIZE_T)((PUCHAR)g_NtosEnd - targetCode);
                if (remaining > 0x1000) remaining = 0x1000;

                if (DisasmWalk(handle, targetCode, remaining,
                               target, ctx, depth + 1)) {
                    result = true;
                    break;
                }
            }

            /* For JMP, stop processing this block */
            if (insn[i].id == X86_INS_JMP) break;
        }

        /* Stop on ret */
        if (insn[i].id == X86_INS_RET) break;
    }

    cs_free(insn, count);
    return result;
}

/*
 * Fallback heuristic: scan for mov rax, [rip+disp] followed within
 * ~30 bytes by lea rcx, [rip+disp], both targeting the data section.
 * This catches the Win11 24H2 pattern where the structures are accessed
 * in a different order than older builds.
 */
static bool FallbackScan(csh handle, PUCHAR code, SIZE_T codeLen, uint64_t baseAddr)
{
    cs_insn *insn;
    size_t count = cs_disasm(handle, code, codeLen, baseAddr, 0, &insn);
    if (count == 0) return false;

    /* Collect all [rip+disp] targets pointing to kernel data section */
    struct RipTarget { uint64_t addr; uint64_t target; int id; /* MOV or LEA */ };
    RipTarget targets[64];
    int numTargets = 0;

    for (size_t i = 0; i < count && numTargets < 64; i++) {
        cs_x86 *x86 = &insn[i].detail->x86;
        if ((insn[i].id == X86_INS_MOV || insn[i].id == X86_INS_LEA) &&
            x86->op_count == 2 &&
            x86->operands[0].type == X86_OP_REG &&
            x86->operands[1].type == X86_OP_MEM &&
            x86->operands[1].mem.base == X86_REG_RIP) {

            uint64_t target = insn[i].address + insn[i].size + x86->operands[1].mem.disp;
            if (target >= (uint64_t)g_NtosBase && target < (uint64_t)g_NtosEnd) {
                targets[numTargets].addr = insn[i].address;
                targets[numTargets].target = target;
                targets[numTargets].id = insn[i].id;
                numTargets++;
            }
        }
    }

    /* Look for a pair: one MOV and one LEA targeting different addresses
     * in the data section, within 30 instructions of each other */
    for (int i = 0; i < numTargets; i++) {
        for (int j = i + 1; j < numTargets && j < i + 8; j++) {
            if (targets[i].target == targets[j].target) continue;

            /* One should be LEA (Resource), one should be MOV (ListHead) */
            PVOID resource = NULL;
            PVOID listHead = NULL;

            if (targets[i].id == X86_INS_LEA)
                resource = (PVOID)targets[i].target;
            else if (targets[i].id == X86_INS_MOV)
                listHead = (PVOID)targets[i].target;

            if (targets[j].id == X86_INS_LEA && !resource)
                resource = (PVOID)targets[j].target;
            else if (targets[j].id == X86_INS_MOV && !listHead)
                listHead = (PVOID)targets[j].target;

            if (resource && listHead) {
                g_ExpFirmwareTableResource = resource;
                g_ExpFirmwareTableProviderListHead = listHead;

                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                           "HypervisorHide: FALLBACK Resource=%p ListHead=%p\n",
                           resource, listHead);
                cs_free(insn, count);
                return true;
            }
        }
    }

    cs_free(insn, count);
    return false;
}

bool LocateExpFirmwareTablePointers(PUCHAR startAddr, SIZE_T maxLen)
{
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return false;

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    /* Method 1: Original VmwareHardenedLoader approach — look for
     * ExAcquireResourceSharedLite call with lea rcx before it */
    struct DisasmContext ctx = {};
    ctx.base = startAddr;
    ctx.maxLen = maxLen;
    ctx.maxDepth = 16;
    ctx.maxInsts = 1000;
    ctx.instCount = 0;
    ctx.pfn_ExAcquireResourceSharedLite =
        UtilGetSystemProcAddress(L"ExAcquireResourceSharedLite");
    ctx.lea_rcx_addr = NULL;
    ctx.lea_rcx_imm = NULL;
    ctx.call_acquire_inst = -1;
    ctx.found = false;

    SIZE_T codeLen = maxLen;
    if (startAddr + codeLen > (PUCHAR)g_NtosEnd)
        codeLen = (SIZE_T)((PUCHAR)g_NtosEnd - startAddr);

    DisasmWalk(handle, startAddr, codeLen,
               (uint64_t)startAddr, &ctx, 0);

    if (g_ExpFirmwareTableResource && g_ExpFirmwareTableProviderListHead) {
        cs_close(&handle);
        return true;
    }

    /* Method 2: Fallback — scan for paired [rip+disp] targets in data section */
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
               "HypervisorHide: primary method failed, trying fallback scan\n");

    g_ExpFirmwareTableResource = NULL;
    g_ExpFirmwareTableProviderListHead = NULL;

    bool fallbackResult = FallbackScan(handle, startAddr, codeLen, (uint64_t)startAddr);

    cs_close(&handle);
    return fallbackResult;
}

} /* extern "C" */
