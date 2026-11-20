/*
*   vmexit_common.c - shared backend-neutral VMX/SVM exit policy
*
*   centralizes CPUID handling, XSETBV validation, VMCALL/VMMCALL
*   authentication, GPR indexing, and CR validation so Intel VMX and AMD SVM
*   never diverge on architectural or stealth behavior.
*
*   ZERO Windows API dependencies — safe to execute in VMX-root / SVM host mode.
*/
#include "hv.h"

UINT64 *
hv_gpr_ptr(PGUEST_REGS regs, UINT32 idx)
{
    switch (idx)
    {
    case 0:  return &regs->rax;
    case 1:  return &regs->rcx;
    case 2:  return &regs->rdx;
    case 3:  return &regs->rbx;
    case 4:  return &regs->rsp;
    case 5:  return &regs->rbp;
    case 6:  return &regs->rsi;
    case 7:  return &regs->rdi;
    case 8:  return &regs->r8;
    case 9:  return &regs->r9;
    case 10: return &regs->r10;
    case 11: return &regs->r11;
    case 12: return &regs->r12;
    case 13: return &regs->r13;
    case 14: return &regs->r14;
    case 15: return &regs->r15;
    default: return &regs->rax;
    }
}

VOID
hv_common_handle_cpuid(PGUEST_REGS regs, BOOLEAN is_amd)
{
    INT32  cpu_info[4] = {0};
    UINT32 leaf    = (UINT32)regs->rax;
    UINT32 subleaf = (UINT32)regs->rcx;

#if STEALTH_CPUID_CACHING
    if (g_stealth_enabled && stealth_is_leaf_invalid(leaf))
    {
        cpu_info[0] = g_stealth_cpuid_cache.invalid_leaf[0];
        cpu_info[1] = g_stealth_cpuid_cache.invalid_leaf[1];
        cpu_info[2] = g_stealth_cpuid_cache.invalid_leaf[2];
        cpu_info[3] = g_stealth_cpuid_cache.invalid_leaf[3];
    }
    else
#endif
    {
        __cpuidex(cpu_info, (int)leaf, (int)subleaf);

        if (g_stealth_enabled)
        {
            if (leaf == CPUID_VERSION_FEATURES)
            {
                //
                // always clear hypervisor present bit (ECX[31]).
                // on Intel, also clear VMX (ECX[5]) + SMX (ECX[6]) to remain
                // consistent with IA32_FEATURE_CONTROL hiding VMX/SMX enables.
                //
                cpu_info[2] &= ~(INT32)(1U << CPUID_HYPERVISOR_BIT);
                if (!is_amd)
                    cpu_info[2] &= ~(INT32)((1U << CPUID_VMX_BIT) | (1U << 6));
            }
            else if (is_amd && leaf == CPUID_EXT_FEATURES)
            {
                cpu_info[2] &= ~(INT32)(1U << CPUID_SVM_BIT);
            }
            else if (is_amd && leaf == CPUID_SVM_INFO)
            {
                cpu_info[0] = cpu_info[1] = cpu_info[2] = cpu_info[3] = 0;
            }
        }
    }

    //
    // x86-64 CPUID ZERO-extends EAX/EBX/ECX/EDX into 64-bit GPRs.
    // cast through UINT32 so bit 31 (e.g. leaf 0x80000000 -> 0x80000008)
    // is never sign-extended into bits 63:32!
    //
    regs->rax = (UINT64)(UINT32)cpu_info[0];
    regs->rbx = (UINT64)(UINT32)cpu_info[1];
    regs->rcx = (UINT64)(UINT32)cpu_info[2];
    regs->rdx = (UINT64)(UINT32)cpu_info[3];
}

BOOLEAN
hv_common_handle_xsetbv(PGUEST_REGS regs)
{
    UINT64 index = regs->rcx;
    UINT64 value = ((UINT64)(UINT32)regs->rdx << 32) | (UINT64)(UINT32)regs->rax;

    //
    // Intel SDM / AMD APM: upper 32 bits of RCX must be 0, only XCR0 (0) is valid
    //
    if ((index & 0xFFFFFFFF00000000ULL) != 0 || (UINT32)index != 0)
        return FALSE;

    if (!stealth_is_xcr0_valid(value))
        return FALSE;

    _xsetbv(0, value);
    return TRUE;
}

BOOLEAN
hv_common_check_vmcall_auth(PGUEST_REGS regs, UINT8 cpl)
{
    if (cpl != 0)
        return FALSE;

    if (regs->r10 != HV_VMCALL_SIG_R10 ||
        regs->r11 != HV_VMCALL_SIG_R11 ||
        regs->r12 != HV_VMCALL_SIG_R12)
        return FALSE;

    return TRUE;
}

BOOLEAN
hv_common_is_synthetic_msr(UINT32 msr)
{
    return (msr >= 0x40000000U && msr <= 0x4FFFFFFFU) ? TRUE : FALSE;
}

BOOLEAN
hv_common_validate_cr0(UINT64 val)
{
    //
    // upper 32 bits of CR0 are reserved (must be 0 -> #GP(0))
    //
    if (val & CR0_RESERVED_HIGH)
        return FALSE;

    //
    // CR0.NW=1 with CR0.CD=0 is illegal (#GP(0))
    //
    if ((val & CR0_NW_FLAG) && !(val & CR0_CD_FLAG))
        return FALSE;

    //
    // CR0.PG=1 with CR0.PE=0 is illegal (#GP(0))
    //
    if ((val & CR0_PG_FLAG) && !(val & CR0_PE_FLAG))
        return FALSE;

    return TRUE;
}

BOOLEAN
hv_common_validate_cr3(UINT64 val)
{
    //
    // ignore bit 63 (PCID no-invalidate bit when CR4.PCIDE=1);
    // bits above MAXPHYADDR (except bit 63) are reserved and must be 0 -> #GP(0)
    //
    UINT64 phys_mask = (1ULL << g_cpu.maxphyaddr) - 1ULL;
    UINT64 check_val = val & ~(1ULL << 63);

    if (check_val & ~phys_mask)
        return FALSE;

    return TRUE;
}

BOOLEAN
hv_common_validate_cr4(UINT64 val)
{
    //
    // reject any bit not architecturally supported on this CPU -> #GP(0)
    //
    if (val & ~g_cpu.cr4_valid_mask)
        return FALSE;

    return TRUE;
}
