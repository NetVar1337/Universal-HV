/*
*   vmexit.c - Intel VMX VM-exit handler and sub-handlers
*   ZERO Windows API dependencies — executes entirely in VMX-root mode.
*/
#include "hv.h"

static __forceinline VOID
vmexit_advance_rip(VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT64 instr_len = 0;
    __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &instr_len);

    UINT64 new_rip = vcpu->vmexit_rip + instr_len;

    //
    // truncate RIP for non-64-bit segments (compatibility mode)
    // CS.L=0 CS.D=1 -> 32-bit, CS.L=0 CS.D=0 -> 16-bit
    //
    size_t cs_ar_raw = 0;
    __vmx_vmread(VMCS_GUEST_CS_ACCESS_RIGHTS, &cs_ar_raw);
    if (!((cs_ar_raw >> 13) & 1))
    {
        if ((cs_ar_raw >> 14) & 1)
            new_rip = (UINT32)new_rip;
        else
            new_rip = (UINT16)new_rip;
    }

    __vmx_vmwrite(VMCS_GUEST_RIP, new_rip);

    //
    // clear STI / MOV-SS interruptibility blocking after completing instruction
    //
    size_t intr_state = 0;
    __vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE, &intr_state);
    if (intr_state & (GUEST_INTR_STATE_BLOCKING_BY_STI | GUEST_INTR_STATE_BLOCKING_BY_MOV_SS))
    {
        intr_state &= ~(size_t)(GUEST_INTR_STATE_BLOCKING_BY_STI | GUEST_INTR_STATE_BLOCKING_BY_MOV_SS);
        __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, intr_state);
    }

    //
    // single-step (TF) + hardware execution breakpoints (fast-path: only touch
    // DR0-DR3 when DR7 actually enables a breakpoint)
    //
    size_t rflags_raw = 0;
    __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags_raw);

    BOOLEAN need_bs = FALSE;
    if (rflags_raw & RFLAGS_TF)
    {
        size_t debugctl_raw = 0;
        __vmx_vmread(VMCS_GUEST_DEBUGCTL, &debugctl_raw);
        if (!(debugctl_raw & DEBUGCTL_BTF))
            need_bs = TRUE;
    }

    UINT64 dr7 = 0;
    __vmx_vmread(VMCS_GUEST_DR7, &dr7);

    UINT64 bp_matched = 0;
    if (dr7 & 0xFFULL)
    {
        static const UINT64 ln_bits[] = { DR7_L0, DR7_L1, DR7_L2, DR7_L3 };
        static const UINT64 gn_bits[] = { DR7_G0, DR7_G1, DR7_G2, DR7_G3 };
        static const UINT64 bn_bits[] = { PENDING_DEBUG_B0, PENDING_DEBUG_B1, PENDING_DEBUG_B2, PENDING_DEBUG_B3 };

        for (int i = 0; i < 4; i++)
        {
            if (!(dr7 & (ln_bits[i] | gn_bits[i])))
                continue;
            if ((dr7 & DR7_RW_MASK(i)) != 0)
                continue;

            UINT64 drn = 0;
            switch (i)
            {
            case 0: drn = __readdr(0); break;
            case 1: drn = __readdr(1); break;
            case 2: drn = __readdr(2); break;
            case 3: drn = __readdr(3); break;
            default: continue;
            }

            if (drn == new_rip)
                bp_matched |= bn_bits[i];
        }
    }

    if (need_bs || bp_matched)
    {
        UINT64 pending = 0;
        __vmx_vmread(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, &pending);

        if (need_bs)
            pending |= PENDING_DEBUG_BS;
        if (bp_matched)
            pending |= bp_matched | PENDING_DEBUG_ENABLED_BP;

        __vmx_vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, pending);
    }
}

//
// exception classification for double-fault generation (SDM Vol 3 Table 6-5)
//
typedef enum {
    EXCEPTION_CLASS_BENIGN,
    EXCEPTION_CLASS_CONTRIBUTORY,
    EXCEPTION_CLASS_PAGE_FAULT,
    EXCEPTION_CLASS_DOUBLE_FAULT
} EXCEPTION_CLASS;

static __forceinline EXCEPTION_CLASS
classify_exception(UINT32 vector)
{
    switch (vector)
    {
    case EXCEPTION_VECTOR_DIVIDE_ERROR:
    case EXCEPTION_VECTOR_INVALID_TSS:
    case EXCEPTION_VECTOR_SEGMENT_NOT_PRESENT:
    case EXCEPTION_VECTOR_STACK_SEGMENT_FAULT:
    case EXCEPTION_VECTOR_GENERAL_PROTECTION:
        return EXCEPTION_CLASS_CONTRIBUTORY;
    case EXCEPTION_VECTOR_PAGE_FAULT:
        return EXCEPTION_CLASS_PAGE_FAULT;
    case EXCEPTION_VECTOR_DOUBLE_FAULT:
        return EXCEPTION_CLASS_DOUBLE_FAULT;
    default:
        return EXCEPTION_CLASS_BENIGN;
    }
}

static __forceinline BOOLEAN
should_generate_df(UINT32 first_vector, UINT32 second_vector)
{
    EXCEPTION_CLASS first  = classify_exception(first_vector);
    EXCEPTION_CLASS second = classify_exception(second_vector);

    if (first == EXCEPTION_CLASS_CONTRIBUTORY && second == EXCEPTION_CLASS_CONTRIBUTORY)
        return TRUE;

    if (first == EXCEPTION_CLASS_PAGE_FAULT &&
        (second == EXCEPTION_CLASS_CONTRIBUTORY || second == EXCEPTION_CLASS_PAGE_FAULT))
        return TRUE;

    return FALSE;
}

static __forceinline UINT8
vmexit_get_guest_cpl(VOID)
{
    size_t cs_ar = 0;
    __vmx_vmread(VMCS_GUEST_CS_ACCESS_RIGHTS, &cs_ar);
    return (UINT8)((cs_ar >> 5) & 3U);
}

static __forceinline VOID
vmexit_set_proc_ctrl_bit(UINT32 bit, BOOLEAN enable)
{
    size_t proc_ctrl = 0;
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
    if (enable)
        proc_ctrl |= (size_t)bit;
    else
        proc_ctrl &= ~(size_t)bit;
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);
}

UINT64
vmx_return_rsp_for_vmxoff(VIRTUAL_MACHINE_STATE * vcpu)
{
    return vcpu->vmxoff.guest_rsp;
}

UINT64
vmx_return_rip_for_vmxoff(VIRTUAL_MACHINE_STATE * vcpu)
{
    return vcpu->vmxoff.guest_rip;
}

UINT64
vmx_return_rflags_for_vmxoff(VIRTUAL_MACHINE_STATE * vcpu)
{
    return vcpu->vmxoff.guest_rflags;
}

VOID
vmexit_handle_cpuid(VIRTUAL_MACHINE_STATE * vcpu)
{
    vcpu->cpuid_exits++;
    hv_common_handle_cpuid(vcpu->regs, FALSE);
}

VOID
vmexit_handle_msr_read(VIRTUAL_MACHINE_STATE * vcpu)
{
    MSR         msr        = {0};
    PGUEST_REGS regs       = vcpu->regs;
    UINT32      target_msr = (UINT32)(regs->rcx & 0xFFFFFFFFU);

    vcpu->msr_exits++;

    if (hv_common_is_synthetic_msr(target_msr))
    {
        vmexit_inject_gp();
        vcpu->advance_rip = FALSE;
        return;
    }

    if ((target_msr <= 0x00001FFFU) ||
        (target_msr >= 0xC0000000U && target_msr <= 0xC0001FFFU))
    {
        switch (target_msr)
        {
        case IA32_SYSENTER_CS:
            __vmx_vmread(VMCS_GUEST_SYSENTER_CS, &msr.Flags);
            break;

        case IA32_SYSENTER_ESP:
            __vmx_vmread(VMCS_GUEST_SYSENTER_ESP, &msr.Flags);
            break;

        case IA32_SYSENTER_EIP:
            __vmx_vmread(VMCS_GUEST_SYSENTER_EIP, &msr.Flags);
            break;

        case IA32_GS_BASE:
            __vmx_vmread(VMCS_GUEST_GS_BASE, &msr.Flags);
            break;

        case IA32_FS_BASE:
            __vmx_vmread(VMCS_GUEST_FS_BASE, &msr.Flags);
            break;

        case 0x10U: // IA32_TIME_STAMP_COUNTER
        {
            if (g_stealth_enabled)
            {
                size_t tsc_offset_raw = 0;
                __vmx_vmread(VMCS_CTRL_TSC_OFFSET, &tsc_offset_raw);
                msr.Flags = (UINT64)((INT64)__rdtsc() + (INT64)tsc_offset_raw);
            }
            else
            {
                msr.Flags = __rdtsc();
            }
            break;
        }

        case IA32_FEATURE_CONTROL:
        {
            IA32_FEATURE_CONTROL_REGISTER feat = {0};
            feat.AsUInt = __readmsr(IA32_FEATURE_CONTROL);

            if (g_stealth_enabled)
            {
                feat.Lock                       = 1;
                feat.EnableVmxInsideSmx         = 0;
                feat.EnableVmxOutsideSmx        = 0;
                feat.SenterLocalFunctionEnables = 0;
                feat.SenterGlobalEnable         = 0;
                feat.SgxLaunchControlEnable     = 0;
                feat.SgxGlobalEnable            = 0;
            }

            msr.Flags = feat.AsUInt;
            break;
        }

        default:
            if (target_msr >= IA32_VMX_BASIC && target_msr <= 0x493U)
            {
                msr.Flags = __readmsr(target_msr);
                break;
            }

            //
            // dynamically traced MSR: log hit into lock-free ring and forward
            //
            if (hv_is_msr_traced(target_msr, FALSE))
            {
                msr.Flags = __readmsr(target_msr);
                logbuf_push_root(vcpu->core_id, HV_LOG_EVT_MSR_READ_TRACE, target_msr, msr.Flags);
                break;
            }

            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
            return;
        }

        if (hv_is_msr_traced(target_msr, FALSE) &&
            (target_msr == IA32_SYSENTER_CS || target_msr == IA32_SYSENTER_ESP ||
             target_msr == IA32_SYSENTER_EIP || target_msr == IA32_FS_BASE ||
             target_msr == IA32_GS_BASE))
        {
            logbuf_push_root(vcpu->core_id, HV_LOG_EVT_MSR_READ_TRACE, target_msr, msr.Flags);
        }

        regs->rax = (UINT64)msr.Fields.Low;
        regs->rdx = (UINT64)msr.Fields.High;
    }
    else
    {
        vmexit_inject_gp();
        vcpu->advance_rip = FALSE;
    }
}

VOID
vmexit_handle_msr_write(VIRTUAL_MACHINE_STATE * vcpu)
{
    MSR         msr        = {0};
    PGUEST_REGS regs       = vcpu->regs;
    UINT32      target_msr = (UINT32)(regs->rcx & 0xFFFFFFFFU);

    vcpu->msr_exits++;

    msr.Fields.Low  = (ULONG)regs->rax;
    msr.Fields.High = (ULONG)regs->rdx;

    if (hv_common_is_synthetic_msr(target_msr))
    {
        vmexit_inject_gp();
        vcpu->advance_rip = FALSE;
        return;
    }

    if (target_msr == IA32_FEATURE_CONTROL ||
        (target_msr >= IA32_VMX_BASIC && target_msr <= 0x493U))
    {
        vmexit_inject_gp();
        vcpu->advance_rip = FALSE;
        return;
    }

    if ((target_msr <= 0x00001FFFU) ||
        (target_msr >= 0xC0000000U && target_msr <= 0xC0001FFFU))
    {
        switch (target_msr)
        {
        case IA32_SYSENTER_CS:
            __vmx_vmwrite(VMCS_GUEST_SYSENTER_CS, msr.Flags);
            break;

        case IA32_SYSENTER_ESP:
            __vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP, msr.Flags);
            break;

        case IA32_SYSENTER_EIP:
            __vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP, msr.Flags);
            break;

        case IA32_GS_BASE:
            __vmx_vmwrite(VMCS_GUEST_GS_BASE, msr.Flags);
            break;

        case IA32_FS_BASE:
            __vmx_vmwrite(VMCS_GUEST_FS_BASE, msr.Flags);
            break;

        default:
            if (hv_is_msr_traced(target_msr, TRUE))
            {
                logbuf_push_root(vcpu->core_id, HV_LOG_EVT_MSR_WRITE_TRACE, target_msr, msr.Flags);
                __writemsr(target_msr, msr.Flags);
                return;
            }

            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
            return;
        }

        if (hv_is_msr_traced(target_msr, TRUE))
            logbuf_push_root(vcpu->core_id, HV_LOG_EVT_MSR_WRITE_TRACE, target_msr, msr.Flags);
    }
    else
    {
        vmexit_inject_gp();
        vcpu->advance_rip = FALSE;
    }
}

VOID
vmexit_handle_mov_cr(VIRTUAL_MACHINE_STATE * vcpu)
{
    VMX_EXIT_QUALIFICATION_MOV_CR cr_qual;
    PGUEST_REGS                   regs = vcpu->regs;
    UINT32                        gpr;
    UINT64 *                      reg_ptr;

    vcpu->cr_exits++;

    cr_qual.AsUInt = vcpu->exit_qual;
    gpr            = (UINT32)cr_qual.GeneralPurposeRegister;
    reg_ptr        = hv_gpr_ptr(regs, gpr);

    switch (cr_qual.AccessType)
    {
    case 0: // MOV to CR
    {
        switch (cr_qual.ControlRegister)
        {
        case 0:
        {
            UINT64   desired = *reg_ptr;
            CR_FIXED fixed;

            if (!hv_common_validate_cr0(desired))
            {
                vmexit_inject_gp();
                vcpu->advance_rip = FALSE;
                return;
            }

            UINT64 actual = desired;
            fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
            actual |= fixed.Fields.Low;
            fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
            actual &= fixed.Fields.Low;

            __vmx_vmwrite(VMCS_GUEST_CR0, actual);
            __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, desired);
            break;
        }

        case 3:
        {
            UINT64 new_cr3 = *reg_ptr;

            if (!hv_common_validate_cr3(new_cr3))
            {
                vmexit_inject_gp();
                vcpu->advance_rip = FALSE;
                return;
            }

            BOOLEAN no_flush = (new_cr3 >> 63) & 1;
            __vmx_vmwrite(VMCS_GUEST_CR3, new_cr3 & ~(1ULL << 63));

            if (!no_flush && g_ept->vpid_enabled && g_ept->invvpid_supported)
            {
                INVVPID_DESCRIPTOR desc = {0};
                desc.Vpid = VPID_TAG;

                UINT8 ret;
                if (g_ept->invvpid_single_retaining_globals)
                    ret = asm_invvpid(InvvpidSingleContextRetainingGlobals, &desc);
                else
                    ret = asm_invvpid(InvvpidSingleContext, &desc);

                if (ret != 0)
                    asm_invvpid(InvvpidAllContexts, &desc);
            }
            break;
        }

        case 8:
        {
            UINT64 desired = *reg_ptr;
            if (desired > 0xFULL)
            {
                vmexit_inject_gp();
                vcpu->advance_rip = FALSE;
                return;
            }

            vcpu->guest_cr8 = (UINT8)desired;
            __writecr8(vcpu->guest_cr8);

            //
            // if an external interrupt was deferred because of CR8 priority,
            // check whether this lower CR8 now unmasks it.
            //
            if (vcpu->has_pending_ext_interrupt && vcpu->defer_ext_by_cr8)
            {
                UINT8 vec_prio = (UINT8)(vcpu->pending_ext_vector >> 4);
                if (vec_prio > vcpu->guest_cr8)
                {
                    vcpu->defer_ext_by_cr8 = FALSE;
                    if (!vcpu->cr8_load_exiting_forced)
                        vmexit_set_proc_ctrl_bit(CPU_BASED_VM_EXEC_CTRL_CR8_LOAD_EXITING, FALSE);

                    //
                    // arm interrupt-window exiting to inject on the next safe boundary
                    // (after MOV CR8 advances RIP and clears STI/MOV-SS blocking).
                    //
                    vmexit_set_proc_ctrl_bit(CPU_BASED_VM_EXEC_CTRL_INTERRUPT_WINDOW_EXITING, TRUE);
                }
            }
            break;
        }

        case 4:
        {
            UINT64   desired = *reg_ptr;
            CR_FIXED fixed;

            if (!hv_common_validate_cr4(desired))
            {
                vmexit_inject_gp();
                vcpu->advance_rip = FALSE;
                return;
            }

            //
            // cannot clear PAE in IA-32e mode
            //
            if (!(desired & CR4_PAE_FLAG))
            {
                vmexit_inject_gp();
                vcpu->advance_rip = FALSE;
                return;
            }

#if STEALTH_HIDE_CR4_VMXE
            if (g_stealth_enabled)
            {
                UINT64 actual = desired | CR4_VMX_ENABLE_FLAG;
                fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED0);
                actual |= fixed.Fields.Low;
                fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED1);
                actual &= fixed.Fields.Low;

                __vmx_vmwrite(VMCS_GUEST_CR4, actual);
                __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, desired & ~CR4_VMX_ENABLE_FLAG);
            }
            else
#endif
            {
                UINT64 actual = desired;
                fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED0);
                actual |= fixed.Fields.Low;
                fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED1);
                actual &= fixed.Fields.Low;

                __vmx_vmwrite(VMCS_GUEST_CR4, actual);
                __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, desired);
            }
            break;
        }

        default:
            break;
        }
        break;
    }

    case 1: // MOV from CR
    {
        switch (cr_qual.ControlRegister)
        {
        case 3:
            __vmx_vmread(VMCS_GUEST_CR3, reg_ptr);
            break;

        case 8:
            *reg_ptr = (UINT64)__readcr8();
            break;

        default:
            break;
        }

        //
        // if destination GPR was RSP (4), write updated value back to VMCS!
        //
        if (gpr == 4)
            __vmx_vmwrite(VMCS_GUEST_RSP, regs->rsp);
        break;
    }

    case 2: // CLTS
    {
        UINT64   guest_cr0 = 0;
        UINT64   shadow    = 0;
        CR_FIXED fixed;

        __vmx_vmread(VMCS_GUEST_CR0, &guest_cr0);
        __vmx_vmread(VMCS_CTRL_CR0_READ_SHADOW, &shadow);

        guest_cr0 &= ~(1ULL << 3);
        shadow    &= ~(1ULL << 3);

        fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
        guest_cr0 |= fixed.Fields.Low;
        fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
        guest_cr0 &= fixed.Fields.Low;

        __vmx_vmwrite(VMCS_GUEST_CR0, guest_cr0);
        __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, shadow);
        break;
    }

    case 3: // LMSW
    {
        UINT64   guest_cr0 = 0;
        UINT64   shadow    = 0;
        CR_FIXED fixed;
        UINT64   src       = (UINT64)(UINT16)cr_qual.LmswSourceData & 0xFULL;

        __vmx_vmread(VMCS_GUEST_CR0, &guest_cr0);
        __vmx_vmread(VMCS_CTRL_CR0_READ_SHADOW, &shadow);

        guest_cr0 = (guest_cr0 & ~0xEULL) | (src & 0xEULL) | ((guest_cr0 | src) & 1ULL);
        shadow    = (shadow    & ~0xEULL) | (src & 0xEULL) | ((shadow    | src) & 1ULL);

        fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
        guest_cr0 |= fixed.Fields.Low;
        fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
        guest_cr0 &= fixed.Fields.Low;

        __vmx_vmwrite(VMCS_GUEST_CR0, guest_cr0);
        __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, shadow);
        break;
    }

    default:
        break;
    }
}

VOID
vmexit_handle_ept_violation(VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT64 guest_phys = 0;
    __vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &guest_phys);

    vcpu->ept_npt_exits++;

    //
    // 1. check if this physical page has an active EPT watchpoint
    //
    INT32 wp_idx = ept_find_watchpoint_root(guest_phys);
    if (wp_idx >= 0)
    {
        logbuf_push_root(vcpu->core_id, HV_LOG_EVT_WATCHPOINT_HIT, guest_phys, vcpu->vmexit_rip);
        ept_watchpoint_disarm_root((UINT32)wp_idx);
        ept_invept_single(vcpu->ept_pointer);

        //
        // single-step the guest via Monitor Trap Flag (MTF) so the faulting
        // instruction executes once, then re-arm the watchpoint on MTF exit.
        //
        vcpu->wp_stepping   = TRUE;
        vcpu->wp_step_index = (UINT32)wp_idx;
        vmexit_set_proc_ctrl_bit(CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG, TRUE);

        vcpu->advance_rip = FALSE;
        return;
    }

    //
    // 2. check if this is an unmapped above-4G MMIO region (e.g. 64-bit PCIe /
    //    Resizable BAR) — dynamically map as UC from pre-allocated DynPool.
    //
    if (ept_handle_dynamic_mmio(guest_phys))
    {
        ept_invept_single(vcpu->ept_pointer);
        logbuf_push_root(vcpu->core_id, HV_LOG_EVT_DYN_MMIO, guest_phys, vcpu->vmexit_rip);
        vcpu->advance_rip = FALSE;
        return;
    }

    vmexit_inject_gp();
    vcpu->advance_rip = FALSE;
}

VOID
vmexit_handle_vmcall(VIRTUAL_MACHINE_STATE * vcpu)
{
    PGUEST_REGS regs = vcpu->regs;

    if (!hv_common_check_vmcall_auth(regs, vmexit_get_guest_cpl()))
    {
        vmexit_inject_ud();
        vcpu->advance_rip = FALSE;
        return;
    }

    switch (regs->rcx)
    {
    case VMCALL_TEST:
        regs->rax = (UINT64)STATUS_SUCCESS;
        break;

    case VMCALL_INVEPT:
        ept_invept_single(vcpu->ept_pointer);
        regs->rax = (UINT64)STATUS_SUCCESS;
        break;

    case VMCALL_VMXOFF:
    {
        UINT64 instr_len   = 0;
        UINT64 guest_cr3   = 0;
        UINT64 guest_rfl   = 0;
        UINT64 guest_gdtr  = 0;
        UINT64 guest_gdtl  = 0;
        UINT64 guest_idtr  = 0;
        UINT64 guest_idtl  = 0;
        UINT64 guest_fs    = 0;
        UINT64 guest_gs    = 0;
        UINT64 guest_tr    = 0;
        UINT64 guest_cr4   = 0;

        //
        // snapshot live per-core guest state from VMCS BEFORE __vmx_off()
        //
        __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &instr_len);
        __vmx_vmread(VMCS_GUEST_CR3,        &guest_cr3);
        __vmx_vmread(VMCS_GUEST_RFLAGS,     &guest_rfl);
        __vmx_vmread(VMCS_GUEST_GDTR_BASE,  &guest_gdtr);
        __vmx_vmread(VMCS_GUEST_GDTR_LIMIT, &guest_gdtl);
        __vmx_vmread(VMCS_GUEST_IDTR_BASE,  &guest_idtr);
        __vmx_vmread(VMCS_GUEST_IDTR_LIMIT, &guest_idtl);
        __vmx_vmread(VMCS_GUEST_FS_BASE,    &guest_fs);
        __vmx_vmread(VMCS_GUEST_GS_BASE,    &guest_gs);
        __vmx_vmread(VMCS_GUEST_TR_SELECTOR, &guest_tr);
        __vmx_vmread(VMCS_GUEST_CR4,        &guest_cr4);

        vcpu->vmxoff.guest_rip    = vcpu->vmexit_rip + instr_len;
        vcpu->vmxoff.guest_rsp    = (UINT64)regs->rsp;
        vcpu->vmxoff.guest_rflags = guest_rfl;
        vcpu->vmxoff.guest_cr3    = guest_cr3;
        vcpu->vmxoff.executed     = TRUE;

        __vmx_off();

        //
        // switch back to guest CR3 before touching guest GDT/IDT/FS/GS
        //
        __writecr3(guest_cr3);

        //
        // restore live per-core IDTR
        //
        asm_reload_idtr((PVOID)guest_idtr, (UINT32)guest_idtl);

        //
        // restore live per-core GDTR and TR (clear busy bit before LTR)
        //
        if (guest_gdtr)
        {
            UINT16 tr_sel = (UINT16)guest_tr;
            if (tr_sel & ~0x7U)
            {
                PSEGMENT_DESCRIPTOR_64 tss_desc = (PSEGMENT_DESCRIPTOR_64)(
                    guest_gdtr + (tr_sel & ~0x7U));
                tss_desc->Type = TSS_TYPE_AVAILABLE_64;
            }

            asm_reload_gdtr((PVOID)guest_gdtr, (UINT32)guest_gdtl);
            if (tr_sel)
                asm_reload_tr(tr_sel);
        }

        //
        // restore live guest FS_BASE / GS_BASE and clear CR4.VMXE
        //
        __writemsr(IA32_FS_BASE, guest_fs);
        __writemsr(IA32_GS_BASE, guest_gs);
        __writecr4(guest_cr4 & ~CR4_VMX_ENABLE_FLAG);

        regs->rax = (UINT64)STATUS_SUCCESS;
        break;
    }

    default:
        regs->rax = (UINT64)STATUS_UNSUCCESSFUL;
        break;
    }
}

VOID
vmexit_handle_triple_fault(VIRTUAL_MACHINE_STATE * vcpu)
{
    vcpu->advance_rip = FALSE;
}

VOID
vmexit_handle_mov_dr(VIRTUAL_MACHINE_STATE * vcpu)
{
    PGUEST_REGS regs      = vcpu->regs;
    UINT64      exit_qual = vcpu->exit_qual;

    UINT32 dr_num  = (UINT32)(exit_qual & 7U);
    UINT32 dir     = (UINT32)((exit_qual >> 4) & 1U);   // 0=to DR, 1=from DR
    UINT32 gpr_idx = (UINT32)((exit_qual >> 8) & 0xFU);

    UINT64 * reg_ptr = hv_gpr_ptr(regs, gpr_idx);

    //
    // DR4/DR5 alias DR6/DR7 when CR4.DE=0, #UD when CR4.DE=1
    //
    if (dr_num == 4 || dr_num == 5)
    {
        UINT64 cr4 = 0;
        __vmx_vmread(VMCS_GUEST_CR4, &cr4);
        if (cr4 & CR4_DE_FLAG)
        {
            vmexit_inject_ud();
            vcpu->advance_rip = FALSE;
            return;
        }
        dr_num = (dr_num == 4) ? 6 : 7;
    }

    //
    // host mode never modifies DR0-DR3/DR6, so access hardware registers directly;
    // DR7 lives in the VMCS guest state field.
    //
    if (dir == 0)
    {
        UINT64 val = *reg_ptr;
        switch (dr_num)
        {
        case 0: __writedr(0, val); break;
        case 1: __writedr(1, val); break;
        case 2: __writedr(2, val); break;
        case 3: __writedr(3, val); break;
        case 6: __writedr(6, val); break;
        case 7:
            __vmx_vmwrite(VMCS_GUEST_DR7, val);
            break;
        default:
            break;
        }
    }
    else
    {
        UINT64 val = 0;
        switch (dr_num)
        {
        case 0: val = __readdr(0); break;
        case 1: val = __readdr(1); break;
        case 2: val = __readdr(2); break;
        case 3: val = __readdr(3); break;
        case 6: val = __readdr(6); break;
        case 7:
            __vmx_vmread(VMCS_GUEST_DR7, &val);
            break;
        default:
            break;
        }
        *reg_ptr = val;

        if (gpr_idx == 4)
            __vmx_vmwrite(VMCS_GUEST_RSP, regs->rsp);
    }
}

BOOLEAN
vmexit_handler(_Inout_ PGUEST_REGS regs, _In_ VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT64  exit_tsc_start = __rdtsc();
    size_t  exit_raw       = 0;
    UINT32  exit_reason    = 0;
    BOOLEAN result         = FALSE;

    vcpu->regs        = regs;
    vcpu->in_root     = TRUE;
    vcpu->advance_rip = TRUE;
    vcpu->exit_count++;

    __vmx_vmread(VMCS_EXIT_REASON, &exit_raw);
    exit_reason       = (UINT32)(exit_raw & 0xFFFFU);
    vcpu->exit_reason = exit_reason;

#if STEALTH_COMPENSATE_TIMING
    if (vcpu->tsc_rdtsc_armed &&
        exit_reason != VMX_EXIT_REASON_EXECUTE_RDTSC &&
        exit_reason != VMX_EXIT_REASON_EXECUTE_RDTSCP)
    {
        vcpu->tsc_rdtsc_armed = FALSE;
        if (!g_stealth_cpuid_cache.rdtsc_exiting_forced)
            vmexit_set_proc_ctrl_bit(CPU_BASED_VM_EXEC_CTRL_RDTSC_EXITING, FALSE);
    }
#endif

    __vmx_vmread(VMCS_GUEST_RIP, &vcpu->vmexit_rip);
    __vmx_vmread(VMCS_GUEST_RSP, &vcpu->regs->rsp);
    __vmx_vmread(VMCS_EXIT_QUALIFICATION, &vcpu->exit_qual);

    switch (exit_reason)
    {
    case VMX_EXIT_REASON_TRIPLE_FAULT:
        vmexit_handle_triple_fault(vcpu);
        break;

    case VMX_EXIT_REASON_EXECUTE_VMCLEAR:
    case VMX_EXIT_REASON_EXECUTE_VMPTRLD:
    case VMX_EXIT_REASON_EXECUTE_VMPTRST:
    case VMX_EXIT_REASON_EXECUTE_VMREAD:
    case VMX_EXIT_REASON_EXECUTE_VMRESUME:
    case VMX_EXIT_REASON_EXECUTE_VMWRITE:
    case VMX_EXIT_REASON_EXECUTE_VMXOFF:
    case VMX_EXIT_REASON_EXECUTE_VMXON:
    case VMX_EXIT_REASON_EXECUTE_VMLAUNCH:
    case VMX_EXIT_REASON_EXECUTE_INVEPT:
    case VMX_EXIT_REASON_EXECUTE_INVVPID:
    case VMX_EXIT_REASON_EXECUTE_GETSEC:
        vmexit_inject_ud();
        vcpu->advance_rip = FALSE;
        break;

    case VMX_EXIT_REASON_EXECUTE_INVD:
        __wbinvd();
        break;

    case VMX_EXIT_REASON_EXECUTE_INVLPG:
    {
        if (g_ept->vpid_enabled && g_ept->invvpid_supported)
        {
            INVVPID_DESCRIPTOR desc = {0};
            desc.Vpid          = VPID_TAG;
            desc.LinearAddress = vcpu->exit_qual;

            if (g_ept->invvpid_individual_addr)
            {
                UINT8 ret = asm_invvpid(InvvpidIndividualAddress, &desc);
                if (ret != 0)
                    asm_invvpid(InvvpidAllContexts, &desc);
            }
            else
            {
                asm_invvpid(InvvpidAllContexts, &desc);
            }
        }
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_RDPMC:
    {
        UINT64 cr4 = 0;
        __vmx_vmread(VMCS_GUEST_CR4, &cr4);

        if (vmexit_get_guest_cpl() != 0 && !(cr4 & CR4_PCE_FLAG))
        {
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
            break;
        }

        UINT32  counter = (UINT32)(vcpu->regs->rcx & 0xFFFFFFFFU);
        BOOLEAN valid   = FALSE;

        if (counter < g_cpu.pmu_gp_counters)
            valid = TRUE;
        else if (counter >= 0x40000000U && (counter - 0x40000000U) < g_cpu.pmu_fixed_counters)
            valid = TRUE;

        if (valid)
        {
            UINT64 val = __readpmc(counter);
            vcpu->regs->rax = val & 0xFFFFFFFFULL;
            vcpu->regs->rdx = val >> 32;
        }
        else
        {
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
        }
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_RDTSC:
    {
        UINT64 tsc        = __rdtsc();
        size_t offset_raw = 0;
        __vmx_vmread(VMCS_CTRL_TSC_OFFSET, &offset_raw);

#if STEALTH_COMPENSATE_TIMING
        if (vcpu->tsc_rdtsc_armed)
        {
            tsc = vcpu->tsc_cpuid_entry
                + g_stealth_cpuid_cache.bare_metal_cpuid_cost
                + (UINT64)(INT64)offset_raw;

            vcpu->tsc_rdtsc_armed = FALSE;
            if (!g_stealth_cpuid_cache.rdtsc_exiting_forced)
                vmexit_set_proc_ctrl_bit(CPU_BASED_VM_EXEC_CTRL_RDTSC_EXITING, FALSE);
        }
        else
#endif
        {
            tsc = (UINT64)((INT64)tsc + (INT64)offset_raw);
        }

        vcpu->regs->rax = tsc & 0xFFFFFFFFULL;
        vcpu->regs->rdx = tsc >> 32;
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_CPUID:
    {
        vmexit_handle_cpuid(vcpu);

#if STEALTH_COMPENSATE_TIMING
        if (g_stealth_enabled)
        {
            vcpu->tsc_cpuid_entry = exit_tsc_start;
            vcpu->tsc_rdtsc_armed = TRUE;
            if (!g_stealth_cpuid_cache.rdtsc_exiting_forced)
                vmexit_set_proc_ctrl_bit(CPU_BASED_VM_EXEC_CTRL_RDTSC_EXITING, TRUE);
        }
#endif
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_RDMSR:
        vmexit_handle_msr_read(vcpu);
        break;

    case VMX_EXIT_REASON_EXECUTE_WRMSR:
        vmexit_handle_msr_write(vcpu);
        break;

    case VMX_EXIT_REASON_MOV_CR:
        vmexit_handle_mov_cr(vcpu);
        break;

    case VMX_EXIT_REASON_MOV_DR:
        vmexit_handle_mov_dr(vcpu);
        break;

    case VMX_EXIT_REASON_EPT_VIOLATION:
        vmexit_handle_ept_violation(vcpu);
        break;

    case VMX_EXIT_REASON_MONITOR_TRAP_FLAG:
    {
        vmexit_set_proc_ctrl_bit(CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG, FALSE);

        if (vcpu->wp_stepping)
        {
            ept_watchpoint_rearm_root(vcpu->wp_step_index);
            ept_invept_single(vcpu->ept_pointer);
            vcpu->wp_stepping = FALSE;
        }

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_EPT_MISCONFIGURATION:
    {
        __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);
        __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_STATE_SHUTDOWN);
        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_VMCALL:
        vmexit_handle_vmcall(vcpu);
        break;

    case VMX_EXIT_REASON_EXECUTE_XSETBV:
    {
        if (!hv_common_handle_xsetbv(vcpu->regs))
        {
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
        }
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_HLT:
        __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_STATE_HLT);
        break;

    case VMX_EXIT_REASON_EXTERNAL_INTERRUPT:
    {
        size_t int_info_raw = 0;
        __vmx_vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION, &int_info_raw);

        VMENTRY_INTERRUPT_INFORMATION int_info;
        int_info.AsUInt = (UINT32)int_info_raw;

        if (int_info.Valid)
        {
            UINT32 vector  = int_info.Vector;
            UINT8  cur_cr8 = (UINT8)__readcr8();
            vcpu->guest_cr8 = cur_cr8;

            size_t rflags_raw = 0;
            size_t intr_state = 0;
            __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags_raw);
            __vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE, &intr_state);

            BOOLEAN if_open =
                (rflags_raw & (1ULL << 9)) &&
                !(intr_state & (GUEST_INTR_STATE_BLOCKING_BY_STI |
                                GUEST_INTR_STATE_BLOCKING_BY_MOV_SS));

            UINT8 vec_prio = (UINT8)(vector >> 4);

            if (if_open && vec_prio > cur_cr8)
            {
                vmexit_inject_interrupt(vector);
            }
            else
            {
                vcpu->pending_ext_vector        = (UINT8)vector;
                vcpu->has_pending_ext_interrupt = TRUE;

                if (if_open && vec_prio <= cur_cr8)
                {
                    //
                    // IF=1 but CR8 masks this vector: trap MOV to CR8 instead
                    // of INTERRUPT_WINDOW_EXITING to avoid an immediate livelock!
                    //
                    vcpu->defer_ext_by_cr8 = TRUE;
                    vmexit_set_proc_ctrl_bit(CPU_BASED_VM_EXEC_CTRL_CR8_LOAD_EXITING, TRUE);
                }
                else
                {
                    vcpu->defer_ext_by_cr8 = FALSE;
                    vmexit_set_proc_ctrl_bit(CPU_BASED_VM_EXEC_CTRL_INTERRUPT_WINDOW_EXITING, TRUE);
                }
            }
        }

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_EXCEPTION_OR_NMI:
    {
        size_t int_info_raw = 0;
        __vmx_vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION, &int_info_raw);

        VMENTRY_INTERRUPT_INFORMATION int_info;
        int_info.AsUInt = (UINT32)int_info_raw;

        if (int_info.Valid)
        {
            if (int_info.InterruptionType == INTERRUPT_TYPE_NMI)
            {
                size_t intr_state = 0;
                __vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE, &intr_state);
                intr_state &= ~(size_t)GUEST_INTR_STATE_BLOCKING_BY_NMI;
                __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, intr_state);
            }

            __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, int_info.AsUInt);

            if (int_info.DeliverErrorCode)
            {
                size_t error_code = 0;
                __vmx_vmread(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE, &error_code);
                __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, error_code);
            }

            if (int_info.InterruptionType == INTERRUPT_TYPE_SOFTWARE_EXCEPTION)
            {
                size_t instr_len = 0;
                __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &instr_len);
                __vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, instr_len);
            }
        }

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_INTERRUPT_WINDOW:
    {
        vmexit_set_proc_ctrl_bit(CPU_BASED_VM_EXEC_CTRL_INTERRUPT_WINDOW_EXITING, FALSE);

        if (vcpu->has_pending_ext_interrupt)
        {
            UINT8 cur_cr8  = (UINT8)__readcr8();
            UINT8 vec_prio = (UINT8)(vcpu->pending_ext_vector >> 4);
            vcpu->guest_cr8 = cur_cr8;

            if (vec_prio > cur_cr8)
            {
                vmexit_inject_interrupt(vcpu->pending_ext_vector);
                vcpu->has_pending_ext_interrupt = FALSE;
                vcpu->defer_ext_by_cr8          = FALSE;
            }
            else
            {
                //
                // IF opened, but CR8 still masks the pending vector — switch
                // to CR8-load exiting so the guest makes forward progress.
                //
                vcpu->defer_ext_by_cr8 = TRUE;
                vmexit_set_proc_ctrl_bit(CPU_BASED_VM_EXEC_CTRL_CR8_LOAD_EXITING, TRUE);
            }
        }

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_NMI_WINDOW:
    {
        vmexit_set_proc_ctrl_bit(CPU_BASED_VM_EXEC_CTRL_NMI_WINDOW_EXITING, FALSE);

        if (vcpu->has_pending_nmi)
        {
            VMENTRY_INTERRUPT_INFORMATION nmi_info = {0};
            nmi_info.Vector           = EXCEPTION_VECTOR_NMI;
            nmi_info.InterruptionType = INTERRUPT_TYPE_NMI;
            nmi_info.Valid            = 1;
            __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, nmi_info.AsUInt);
            vcpu->has_pending_nmi = FALSE;
        }

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_MWAIT:
    case VMX_EXIT_REASON_EXECUTE_MONITOR:
    case VMX_EXIT_REASON_EXECUTE_PAUSE:
        break;

    case VMX_EXIT_REASON_EXECUTE_RDTSCP:
    {
        unsigned int aux  = 0;
        UINT64       tsc  = __rdtscp(&aux);
        size_t offset_raw = 0;
        __vmx_vmread(VMCS_CTRL_TSC_OFFSET, &offset_raw);

#if STEALTH_COMPENSATE_TIMING
        if (vcpu->tsc_rdtsc_armed)
        {
            tsc = vcpu->tsc_cpuid_entry
                + g_stealth_cpuid_cache.bare_metal_cpuid_cost
                + (UINT64)(INT64)offset_raw;

            vcpu->tsc_rdtsc_armed = FALSE;
            if (!g_stealth_cpuid_cache.rdtsc_exiting_forced)
                vmexit_set_proc_ctrl_bit(CPU_BASED_VM_EXEC_CTRL_RDTSC_EXITING, FALSE);
        }
        else
#endif
        {
            tsc = (UINT64)((INT64)tsc + (INT64)offset_raw);
        }

        vcpu->regs->rax = tsc & 0xFFFFFFFFULL;
        vcpu->regs->rdx = tsc >> 32;
        vcpu->regs->rcx = (UINT64)aux;
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_WBINVD:
        __wbinvd();
        break;

    default:
        logbuf_push_root(vcpu->core_id, HV_LOG_EVT_UNHANDLED_EXIT, exit_reason, vcpu->exit_qual);
        break;
    }

    //
    // re-inject IDT vectoring event if one was in progress during this VM-exit
    //
    if (!vcpu->vmxoff.executed)
    {
        size_t idt_vec_raw = 0;
        __vmx_vmread(VMCS_IDT_VECTORING_INFORMATION, &idt_vec_raw);

        VMENTRY_INTERRUPT_INFORMATION idt_vec;
        idt_vec.AsUInt = (UINT32)idt_vec_raw;

        if (idt_vec.Valid)
        {
            BOOLEAN reinject_idt = TRUE;

            if (exit_reason == VMX_EXIT_REASON_EXCEPTION_OR_NMI)
            {
                size_t exit_int_raw = 0;
                __vmx_vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION, &exit_int_raw);

                VMENTRY_INTERRUPT_INFORMATION exit_int;
                exit_int.AsUInt = (UINT32)exit_int_raw;

                if (exit_int.Valid &&
                    idt_vec.InterruptionType == INTERRUPT_TYPE_HARDWARE_EXCEPTION &&
                    exit_int.InterruptionType == INTERRUPT_TYPE_HARDWARE_EXCEPTION)
                {
                    if (classify_exception(idt_vec.Vector) == EXCEPTION_CLASS_DOUBLE_FAULT)
                    {
                        __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);
                        __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_STATE_SHUTDOWN);
                        reinject_idt = FALSE;
                    }
                    else if (should_generate_df(idt_vec.Vector, exit_int.Vector))
                    {
                        vmexit_inject_df();
                        reinject_idt = FALSE;
                    }
                }
            }

            if (reinject_idt)
            {
                size_t entry_info_raw = 0;
                __vmx_vmread(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, &entry_info_raw);

                VMENTRY_INTERRUPT_INFORMATION entry_info;
                entry_info.AsUInt = (UINT32)entry_info_raw;

                if (entry_info.Valid && entry_info.InterruptionType == INTERRUPT_TYPE_NMI)
                {
                    vcpu->has_pending_nmi = TRUE;
                    vmexit_set_proc_ctrl_bit(CPU_BASED_VM_EXEC_CTRL_NMI_WINDOW_EXITING, TRUE);
                }

                __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, idt_vec.AsUInt);

                if (idt_vec.DeliverErrorCode)
                {
                    size_t idt_err = 0;
                    __vmx_vmread(VMCS_IDT_VECTORING_ERROR_CODE, &idt_err);
                    __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, idt_err);
                }

                if (idt_vec.InterruptionType == INTERRUPT_TYPE_SOFTWARE_EXCEPTION ||
                    idt_vec.InterruptionType == INTERRUPT_TYPE_SOFTWARE_INTERRUPT)
                {
                    size_t instr_len = 0;
                    __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &instr_len);
                    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, instr_len);
                }
            }

            vcpu->advance_rip = FALSE;
        }
    }

    //
    // check per-core NMI flag stored at [vmm_stack + VMM_STACK_SIZE - 0x18]
    // by asm_host_nmi_handler (zero globals — strictly delivered to THIS core).
    //
#if USE_PRIVATE_HOST_IDT
    if (!vcpu->vmxoff.executed)
    {
        volatile LONG *nmi_flag = (volatile LONG *)(vcpu->vmm_stack + VMM_STACK_SIZE - VMM_STACK_NMI_OFFSET);
        if (_InterlockedExchange(nmi_flag, 0))
        {
            if (!vcpu->has_pending_nmi)
            {
                vcpu->has_pending_nmi = TRUE;
                vmexit_set_proc_ctrl_bit(CPU_BASED_VM_EXEC_CTRL_NMI_WINDOW_EXITING, TRUE);
            }
        }
    }
#endif

    if (!vcpu->vmxoff.executed && vcpu->advance_rip)
        vmexit_advance_rip(vcpu);

    if (vcpu->vmxoff.executed)
        result = TRUE;

    //
    // update per-vCPU cycle profiler
    //
    {
        UINT64 elapsed = __rdtsc() - exit_tsc_start;
        vcpu->total_exit_cycles += elapsed;
        if (elapsed < vcpu->min_exit_cycles)
            vcpu->min_exit_cycles = elapsed;
        if (elapsed > vcpu->max_exit_cycles)
            vcpu->max_exit_cycles = elapsed;
    }

    vcpu->in_root = FALSE;
    return result;
}
