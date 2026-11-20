/*
*   svm.c - AMD SVM (AMD-V) backend
*
*   AMD APM Vol 2 compliant implementation:
*     - Real VMLOAD -> VMRUN -> VMSAVE loop in AsmSvm.asm (hardware populates
*       HSAVE automatically; never pokes opaque HSAVE offsets)
*     - True x86-64 NPT tables built by ept.c + valid G_PAT in VMCB
*     - Compressed AMD VMCB 16-bit segment attributes (svm_pack_attrib)
*     - vmcb->Save.Efer keeps EFER.SVME=1 (required by VMRUN); MSRPM intercepts
*       EFER/VM_CR/VM_HSAVE_PA/TSC/VMX MSRs to hide SVME and emulate stealth
*     - Uses VMCB_CTRL_NEXT_RIP (NRIPS) for RIP advancement
*     - No unconditional CR/DR intercepts (fast native guest execution)
*     - Clean VMCALL_VMXOFF exit: restores guest CR3/GDTR/IDTR/hidden state,
*       executes STGI with IF=0, clears EFER.SVME, and returns natively so all
*       VMCB/HSAVE/NPT resources can be freed safely
*     - ZERO Windows API calls inside svm_exit_handler
*/
#include "hv.h"

static __forceinline VOID
svm_inject_exc(PVMCB vmcb, UINT32 vector, BOOLEAN with_err, UINT32 err)
{
    UINT32 inj = SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_EXEPT | (vector & SVM_EVTINJ_VEC_MASK);
    if (with_err)
        inj |= SVM_EVTINJ_VALID_ERR;
    svm_ctrl_write32(vmcb, VMCB_CTRL_EVENT_INJ, inj);
    svm_ctrl_write32(vmcb, VMCB_CTRL_EVENT_INJ_ERR, err);
}

static __forceinline VOID
svm_inject_ud(PVMCB vmcb)
{
    svm_inject_exc(vmcb, EXCEPTION_VECTOR_UNDEFINED_OPCODE, FALSE, 0);
}

static __forceinline VOID
svm_inject_gp(PVMCB vmcb)
{
    svm_inject_exc(vmcb, EXCEPTION_VECTOR_GENERAL_PROTECTION, TRUE, 0);
}

static VOID
svm_fill_segment(PSVM_SEGMENT dest, UINT64 gdt_base, UINT16 selector)
{
    VMX_SEGMENT_SELECTOR seg = {0};

    segment_get_descriptor((PUCHAR)gdt_base, selector, &seg);

    dest->Selector = selector;
    dest->Attrib   = (selector == 0) ? 0 : svm_pack_attrib(seg.Attributes.AsUInt);
    dest->Limit    = seg.Limit;
    dest->Base     = seg.Base;
}

static UINT64
svm_compute_next_rip(PVMCB vmcb)
{
    if (g_cpu.svm_features & SVM_FEATURE_NRIPS)
    {
        UINT64 next_rip = svm_ctrl_read(vmcb, VMCB_CTRL_NEXT_RIP);
        if (next_rip != 0)
            return next_rip;
    }

    //
    // fallback if NRIPS is unavailable: decode length from guest instruction bytes
    //
    UINT8 insn_len = *(PUINT8)((PUINT8)vmcb->Control + VMCB_CTRL_INSN_LEN);
    if (insn_len == 0)
        insn_len = 2; // CPUID, RDMSR, WRMSR, INVD, WBINVD are all 2 bytes
    return vmcb->Save.Rip + insn_len;
}

UINT64
svm_return_rsp_for_off(VIRTUAL_MACHINE_STATE * vcpu)
{
    return vcpu->vmxoff.guest_rsp;
}

UINT64
svm_return_rip_for_off(VIRTUAL_MACHINE_STATE * vcpu)
{
    return vcpu->vmxoff.guest_rip;
}

UINT64
svm_return_rflags_for_off(VIRTUAL_MACHINE_STATE * vcpu)
{
    return vcpu->vmxoff.guest_rflags;
}

static VOID
svm_handle_msr(PVMCB vmcb, VIRTUAL_MACHINE_STATE * vcpu, PGUEST_REGS regs, BOOLEAN is_write, BOOLEAN * advance)
{
    UINT32 msr   = (UINT32)(regs->rcx & 0xFFFFFFFFU);
    UINT64 value = ((UINT64)(UINT32)regs->rdx << 32) | (UINT64)(UINT32)regs->rax;

    vcpu->msr_exits++;

    //
    // hypervisor synthetic MSRs, Intel-only VMX MSRs, and SVM control MSRs -> #GP
    //
    if (hv_common_is_synthetic_msr(msr) ||
        (msr >= IA32_VMX_BASIC && msr <= 0x493U) ||
        msr == IA32_FEATURE_CONTROL ||
        msr == MSR_VM_CR || msr == MSR_VM_HSAVE_PA)
    {
        svm_inject_gp(vmcb);
        *advance = FALSE;
        return;
    }

    if (is_write)
    {
        switch (msr)
        {
        case MSR_EFER:
            //
            // VMRUN requires EFER.SVME=1 in vmcb->Save.Efer; keep SVME=1 in
            // hardware/VMCB while masking it off on guest RDMSR(MSR_EFER).
            //
            vmcb->Save.Efer = value | EFER_SVME;
            break;

        default:
            if (hv_is_msr_traced(msr, TRUE))
            {
                logbuf_push_root(vcpu->core_id, HV_LOG_EVT_MSR_WRITE_TRACE, msr, value);
                __writemsr(msr, value);
            }
            else
            {
                svm_inject_gp(vmcb);
                *advance = FALSE;
            }
            break;
        }
    }
    else
    {
        UINT64 result = 0;

        switch (msr)
        {
        case 0x10U: // IA32_TIME_STAMP_COUNTER
        {
            UINT64 tsc_offset = svm_ctrl_read(vmcb, VMCB_CTRL_TSC_OFFSET);
            result = (UINT64)((INT64)__rdtsc() + (INT64)tsc_offset);
            break;
        }

        case MSR_EFER:
            result = vmcb->Save.Efer & ~EFER_SVME;
            break;

        default:
            if (hv_is_msr_traced(msr, FALSE))
            {
                result = __readmsr(msr);
                logbuf_push_root(vcpu->core_id, HV_LOG_EVT_MSR_READ_TRACE, msr, result);
            }
            else
            {
                svm_inject_gp(vmcb);
                *advance = FALSE;
                return;
            }
            break;
        }

        regs->rax = result & 0xFFFFFFFFULL;
        regs->rdx = result >> 32;
    }
}

static BOOLEAN
svm_handle_vmmcall(PVMCB vmcb, VIRTUAL_MACHINE_STATE * vcpu, PGUEST_REGS regs, BOOLEAN * advance)
{
    if (!hv_common_check_vmcall_auth(regs, vmcb->Save.Cpl))
    {
        svm_inject_ud(vmcb);
        *advance = FALSE;
        return FALSE;
    }

    switch (regs->rcx)
    {
    case VMCALL_TEST:
        regs->rax = (UINT64)STATUS_SUCCESS;
        return FALSE;

    case VMCALL_INVEPT:
        svm_ctrl_write32(vmcb, VMCB_CTRL_TLB_CTL, SVM_TLB_FLUSH_ASID);
        regs->rax = (UINT64)STATUS_SUCCESS;
        return FALSE;

    case VMCALL_VMXOFF:
    {
        //
        // clean AMD SVM exit (AMD APM Vol 2):
        //   1. Save guest RIP/RSP/RFLAGS for SvmOffPath.
        //   2. Ensure IF=0 (CLI), switch CR3 back to guest CR3.
        //   3. Restore live guest IDTR and GDTR.
        //   4. VMLOAD guest VMCB to restore FS/GS/TR/LDTR/KernelGsBase/LSTAR/...
        //   5. STGI (requires EFER.SVME==1; safe because IF==0).
        //   6. Clear EFER.SVME (CPU is now 100% out of SVM mode).
        //   7. Return TRUE -> SvmOffPath restores GPRs/XMM/RFLAGS/RSP -> guest RIP!
        //
        UINT64 next_rip = svm_compute_next_rip(vmcb);

        vcpu->vmxoff.guest_rip    = next_rip;
        vcpu->vmxoff.guest_rsp    = vmcb->Save.Rsp;
        vcpu->vmxoff.guest_rflags = vmcb->Save.Rflags;
        vcpu->vmxoff.guest_cr3    = vmcb->Save.Cr3;
        vcpu->svm_off             = TRUE;
        *advance                  = FALSE;

        _disable();

        __writecr3(vmcb->Save.Cr3);
        asm_reload_idtr((PVOID)vmcb->Save.Idtr.Base, vmcb->Save.Idtr.Limit);
        asm_reload_gdtr((PVOID)vmcb->Save.Gdtr.Base, vmcb->Save.Gdtr.Limit);

        asm_svm_vmload(vcpu->vmcb_pa);
        asm_stgi();
        asm_svm_disable();

        regs->rax = (UINT64)STATUS_SUCCESS;
        return TRUE;
    }

    default:
        regs->rax = (UINT64)STATUS_UNSUCCESSFUL;
        return FALSE;
    }
}

/*
*   svm_exit_handler — C entry from AsmSvm.asm SvmLoop.
*   returns TRUE when tearing down SVM (SvmOffPath), FALSE to resume VMRUN.
*   ZERO Windows API calls!
*/
BOOLEAN
svm_exit_handler(_Inout_ PGUEST_REGS regs, _In_ VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT64  exit_tsc_start = __rdtsc();
    PVMCB   vmcb           = (PVMCB)vcpu->vmcb_va;
    UINT64  exit_code      = svm_ctrl_read(vmcb, VMCB_CTRL_EXIT_CODE);
    UINT64  info1          = svm_ctrl_read(vmcb, VMCB_CTRL_EXIT_INFO1);
    UINT64  info2          = svm_ctrl_read(vmcb, VMCB_CTRL_EXIT_INFO2);
    BOOLEAN advance        = TRUE;
    BOOLEAN do_svm_off     = FALSE;

    //
    // reset one-shot TLB flush control from any previous exit
    //
    svm_ctrl_write32(vmcb, VMCB_CTRL_TLB_CTL, SVM_TLB_DO_NOTHING);

    vcpu->regs        = regs;
    vcpu->in_root     = TRUE;
    vcpu->exit_reason = (UINT32)exit_code;
    vcpu->exit_qual   = info2;
    vcpu->exit_count++;

    //
    // guest RAX/RSP/RIP live in VMCB save area
    //
    regs->rax        = vmcb->Save.Rax;
    regs->rsp        = vmcb->Save.Rsp;
    vcpu->vmexit_rip = vmcb->Save.Rip;

    switch (exit_code)
    {
    case SVM_EXIT_CPUID:
        vcpu->cpuid_exits++;
        hv_common_handle_cpuid(regs, TRUE);
        break;

    case SVM_EXIT_MSR:
        svm_handle_msr(vmcb, vcpu, regs, (info1 & 1ULL) ? TRUE : FALSE, &advance);
        break;

    case SVM_EXIT_VMMCALL:
        do_svm_off = svm_handle_vmmcall(vmcb, vcpu, regs, &advance);
        break;

    //
    // SVM instructions in guest -> #UD (matches bare metal with SVM hidden)
    //
    case SVM_EXIT_VMRUN:
    case SVM_EXIT_VMLOAD:
    case SVM_EXIT_VMSAVE:
    case SVM_EXIT_STGI:
    case SVM_EXIT_CLGI:
    case SVM_EXIT_SKINIT:
        svm_inject_ud(vmcb);
        advance = FALSE;
        break;

    case SVM_EXIT_XSETBV:
        if (!hv_common_handle_xsetbv(regs))
        {
            svm_inject_gp(vmcb);
            advance = FALSE;
        }
        break;

    case SVM_EXIT_INVD:
    case SVM_EXIT_WBINVD:
        __wbinvd();
        break;

    case SVM_EXIT_NPF:
    {
        vcpu->ept_npt_exits++;

        //
        // 1. check for an active NPT 4KB watchpoint on this GPA (info2)
        //
        INT32 wp_idx = ept_find_watchpoint_root(info2);
        if (wp_idx >= 0)
        {
            logbuf_push_root(vcpu->core_id, HV_LOG_EVT_WATCHPOINT_HIT, info2, vcpu->vmexit_rip);
            ept_watchpoint_disarm_root((UINT32)wp_idx);
            svm_ctrl_write32(vmcb, VMCB_CTRL_TLB_CTL, SVM_TLB_FLUSH_ASID);

            //
            // single-step via #DB intercept + guest RFLAGS.TF, then re-arm
            //
            vcpu->wp_stepping   = TRUE;
            vcpu->wp_step_index = (UINT32)wp_idx;
            vcpu->wp_saved_tf   = (vmcb->Save.Rflags & RFLAGS_TF) ? TRUE : FALSE;
            vmcb->Save.Rflags  |= RFLAGS_TF;
            svm_set_intercept(vmcb, SVM_INT_EXCEPTION_BASE + EXCEPTION_VECTOR_DEBUG);

            advance = FALSE;
            break;
        }

        //
        // 2. check if unmapped above-4G MMIO (64-bit PCIe / Resizable BAR)
        //
        if (ept_handle_dynamic_mmio(info2))
        {
            svm_ctrl_write32(vmcb, VMCB_CTRL_TLB_CTL, SVM_TLB_FLUSH_ASID);
            logbuf_push_root(vcpu->core_id, HV_LOG_EVT_DYN_MMIO, info2, vcpu->vmexit_rip);
            advance = FALSE;
            break;
        }

        svm_inject_gp(vmcb);
        advance = FALSE;
        break;
    }

    case (SVM_EXIT_EXCP_BASE + EXCEPTION_VECTOR_DEBUG):
    {
        if (vcpu->wp_stepping)
        {
            svm_clear_intercept(vmcb, SVM_INT_EXCEPTION_BASE + EXCEPTION_VECTOR_DEBUG);
            if (!vcpu->wp_saved_tf)
                vmcb->Save.Rflags &= ~RFLAGS_TF;
            ept_watchpoint_rearm_root(vcpu->wp_step_index);
            svm_ctrl_write32(vmcb, VMCB_CTRL_TLB_CTL, SVM_TLB_FLUSH_ASID);
            vcpu->wp_stepping = FALSE;

            if (vcpu->wp_saved_tf)
                svm_inject_exc(vmcb, EXCEPTION_VECTOR_DEBUG, FALSE, 0);
        }
        else
        {
            svm_inject_exc(vmcb, EXCEPTION_VECTOR_DEBUG, FALSE, 0);
        }
        advance = FALSE;
        break;
    }

    case SVM_EXIT_SHUTDOWN:
        advance = FALSE;
        break;

    default:
        logbuf_push_root(vcpu->core_id, HV_LOG_EVT_UNHANDLED_EXIT, exit_code, info2);
        advance = FALSE;
        break;
    }

    if (!do_svm_off)
    {
        if (advance)
            vmcb->Save.Rip = svm_compute_next_rip(vmcb);

        vmcb->Save.Rax = regs->rax;
    }

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
    return do_svm_off;
}

BOOLEAN
svm_check_support(VOID)
{
    if (!cpuinfo_svm_check())
        return FALSE;

    if (!(g_cpu.svm_features & SVM_FEATURE_NP))
    {
        HV_LOG("SVM: nested paging (NPT) not supported on this CPU\n");
        return FALSE;
    }

    if (g_cpu.svm_num_asids < 2)
    {
        HV_LOG("SVM: insufficient ASIDs (%u)\n", g_cpu.svm_num_asids);
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
svm_virtualize_cpu(PVOID guest_stack)
{
    ULONG                   idx  = hv_current_processor_index();
    VIRTUAL_MACHINE_STATE * vcpu = NULL;
    PVMCB                   vmcb;
    UINT64                  gdt_base;

    if (!g_vcpu || idx >= g_vcpu_capacity)
        return FALSE;

    vcpu = &g_vcpu[idx];
    if (vcpu->launched)
        return TRUE;

    vcpu->proc_index = idx;
    vcpu->core_id    = idx;
    vcpu->asid       = 1;
    vcpu->svm_off    = FALSE;

    vmcb = (PVMCB)vcpu->vmcb_va;
    RtlZeroMemory(vmcb, PAGE_SIZE);

    //
    // intercept only what is required (no unconditional CR/DR exits!)
    //
    svm_set_intercept(vmcb, SVM_INT_CPUID);
    svm_set_intercept(vmcb, SVM_INT_MSR_PROT);
    svm_set_intercept(vmcb, SVM_INT_VMMCALL);
    svm_set_intercept(vmcb, SVM_INT_VMRUN);
    svm_set_intercept(vmcb, SVM_INT_VMLOAD);
    svm_set_intercept(vmcb, SVM_INT_VMSAVE);
    svm_set_intercept(vmcb, SVM_INT_STGI);
    svm_set_intercept(vmcb, SVM_INT_CLGI);
    svm_set_intercept(vmcb, SVM_INT_SKINIT);
    svm_set_intercept(vmcb, SVM_INT_XSETBV);
    svm_set_intercept(vmcb, SVM_INT_INVD);
    svm_set_intercept(vmcb, SVM_INT_WBINVD);
    svm_set_intercept(vmcb, SVM_INT_SHUTDOWN);

    svm_ctrl_write(vmcb, VMCB_CTRL_IOPM_BASE_PA,  vcpu->iopm_pa);
    svm_ctrl_write(vmcb, VMCB_CTRL_MSRPM_BASE_PA, vcpu->msrpm_pa);
    svm_ctrl_write(vmcb, VMCB_CTRL_TSC_OFFSET,    0);
    svm_ctrl_write32(vmcb, VMCB_CTRL_ASID,        vcpu->asid);
    svm_ctrl_write32(vmcb, VMCB_CTRL_TLB_CTL,     SVM_TLB_DO_NOTHING);
    svm_ctrl_write32(vmcb, VMCB_CTRL_INT_CTL,     0);
    svm_ctrl_write32(vmcb, VMCB_CTRL_EVENT_INJ,   0);
    svm_ctrl_write32(vmcb, VMCB_CTRL_EVENT_INJ_ERR, 0);

    //
    // nested paging (shared x86-64 NPT table built by ept_init)
    //
    svm_ctrl_write(vmcb, VMCB_CTRL_MISC_CTL,   SVM_MISC_ENABLE_NP);
    svm_ctrl_write(vmcb, VMCB_CTRL_NESTED_CR3, ept_pml4_pa());

    //
    // enable SVM on this logical processor and register HSAVE PA BEFORE VMSAVE
    //
    asm_svm_enable();
    __writemsr(MSR_VM_HSAVE_PA, vcpu->hsave_pa);

    //
    // capture hidden segment/syscall state (FS/GS/TR/LDTR/KernelGsBase/STAR/
    // LSTAR/CSTAR/SFMASK/SYSENTER_*) into both guest VMCB and host VMCB!
    //
    asm_svm_vmsave(vcpu->vmcb_pa);
    asm_svm_vmsave(vcpu->svm_host_vmcb_pa);

    //
    // populate guest visible architectural state in VMCB save area
    //
    gdt_base = asm_get_gdt_base();
    vcpu->original_idt_base  = asm_get_idt_base();
    vcpu->original_idt_limit = asm_get_idt_limit();

#if USE_PRIVATE_HOST_GDT
    hostgdt_populate_for_vcpu(vcpu);
#else
    vcpu->original_gdt_base    = gdt_base;
    vcpu->original_gdt_limit   = asm_get_gdt_limit();
    vcpu->original_tr_selector = asm_get_tr();
#endif

    svm_fill_segment(&vmcb->Save.Es, gdt_base, asm_get_es());
    svm_fill_segment(&vmcb->Save.Cs, gdt_base, asm_get_cs());
    svm_fill_segment(&vmcb->Save.Ss, gdt_base, asm_get_ss());
    svm_fill_segment(&vmcb->Save.Ds, gdt_base, asm_get_ds());

    vmcb->Save.Gdtr.Selector = 0;
    vmcb->Save.Gdtr.Attrib   = 0;
    vmcb->Save.Gdtr.Limit    = asm_get_gdt_limit();
    vmcb->Save.Gdtr.Base     = gdt_base;

    vmcb->Save.Idtr.Selector = 0;
    vmcb->Save.Idtr.Attrib   = 0;
    vmcb->Save.Idtr.Limit    = vcpu->original_idt_limit;
    vmcb->Save.Idtr.Base     = vcpu->original_idt_base;

    vmcb->Save.Cr0    = __readcr0();
    vmcb->Save.Cr3    = __readcr3();
    vmcb->Save.Cr4    = __readcr4();
    vmcb->Save.Dr6    = __readdr(6);
    vmcb->Save.Dr7    = __readdr(7);
    vmcb->Save.Efer   = __readmsr(MSR_EFER) | EFER_SVME;    // VMRUN requires SVME=1!
    vmcb->Save.GPat   = __readmsr(IA32_PAT);                // required for NPT caching!
    vmcb->Save.Rflags = asm_get_rflags();
    vmcb->Save.Rip    = (UINT64)asm_svm_restore_state;
    vmcb->Save.Rsp    = (UINT64)guest_stack;
    vmcb->Save.Rax    = 0;
    vmcb->Save.Cpl    = 0;

    //
    // VMM stack top slots (H = stack_top - 0x30):
    //   [top - 0x08] = vcpu
    //   [top - 0x10] = guest_vmcb_pa
    //   [top - 0x18] = host_nmi_pending (0)
    //   [top - 0x20] = host_vmcb_pa
    //
    UINT64 stack_top = vcpu->vmm_stack + VMM_STACK_SIZE;
    *(PVIRTUAL_MACHINE_STATE *)(stack_top - VMM_STACK_VCPU_OFFSET) = vcpu;
    *(UINT64 *)(stack_top - VMM_STACK_VMCB_OFFSET)                 = vcpu->vmcb_pa;
    *(UINT64 *)(stack_top - VMM_STACK_NMI_OFFSET)                  = 0;
    *(UINT64 *)(stack_top - VMM_STACK_RSP_OFFSET)                  = vcpu->svm_host_vmcb_pa;

    UINT64 host_cr3  = 0;
    UINT64 host_idtr = 0;

#if USE_PRIVATE_HOST_CR3
    host_cr3 = hostcr3_get();
#endif
#if USE_PRIVATE_HOST_IDT
    if (g_host_idt.initialized)
        host_idtr = hostidt_get_base();
#endif

    vcpu->launched = TRUE;

    //
    // enters host VMLOAD/VMRUN/VMSAVE loop; guest resumes at asm_svm_restore_state
    //
    asm_svm_launch_loop(vcpu, stack_top, host_cr3, host_idtr);

    //
    // unreachable
    //
    return TRUE;
}

VOID
svm_terminate_cpu(VOID)
{
    asm_svm_vmcall(VMCALL_VMXOFF, 0, 0, 0);
}

static BOOLEAN
svm_alloc_vcpu_resources(VIRTUAL_MACHINE_STATE * vcpu)
{
    vcpu->vmm_stack = (UINT64)hv_alloc_aligned_contiguous(
        VMM_STACK_SIZE, VMM_STACK_SIZE, &vcpu->vmm_stack_raw);
    if (!vcpu->vmm_stack)
        return FALSE;
    RtlZeroMemory((PVOID)vcpu->vmm_stack, VMM_STACK_SIZE);

    vcpu->vmcb_va = (UINT64)hv_alloc_contiguous(VMCB_SIZE);
    if (!vcpu->vmcb_va)
        return FALSE;
    RtlZeroMemory((PVOID)vcpu->vmcb_va, VMCB_SIZE);
    vcpu->vmcb_pa = va_to_pa((PVOID)vcpu->vmcb_va);

    vcpu->hsave_va = (UINT64)hv_alloc_contiguous(PAGE_SIZE);
    if (!vcpu->hsave_va)
        return FALSE;
    RtlZeroMemory((PVOID)vcpu->hsave_va, PAGE_SIZE);
    vcpu->hsave_pa = va_to_pa((PVOID)vcpu->hsave_va);

    vcpu->svm_host_vmcb_va = (UINT64)hv_alloc_contiguous(PAGE_SIZE);
    if (!vcpu->svm_host_vmcb_va)
        return FALSE;
    RtlZeroMemory((PVOID)vcpu->svm_host_vmcb_va, PAGE_SIZE);
    vcpu->svm_host_vmcb_pa = va_to_pa((PVOID)vcpu->svm_host_vmcb_va);

    vcpu->iopm_va = (UINT64)hv_alloc_contiguous(IOPM_SIZE);
    if (!vcpu->iopm_va)
        return FALSE;
    RtlZeroMemory((PVOID)vcpu->iopm_va, IOPM_SIZE);
    vcpu->iopm_pa = va_to_pa((PVOID)vcpu->iopm_va);

    vcpu->msrpm_va = (UINT64)hv_alloc_contiguous(MSRPM_SIZE);
    if (!vcpu->msrpm_va)
        return FALSE;
    RtlZeroMemory((PVOID)vcpu->msrpm_va, MSRPM_SIZE);

    //
    // program MSRPM intercepts so guest RDMSR/WRMSR of sensitive MSRs trap!
    //
    PUINT8 msrpm = (PUINT8)vcpu->msrpm_va;
    svm_set_msrpm_bit(msrpm, 0x10U,               TRUE,  FALSE); // IA32_TIME_STAMP_COUNTER
    svm_set_msrpm_bit(msrpm, MSR_EFER,            TRUE,  TRUE);  // hide EFER.SVME
    svm_set_msrpm_bit(msrpm, MSR_VM_CR,           TRUE,  TRUE);  // #GP on guest access
    svm_set_msrpm_bit(msrpm, MSR_VM_HSAVE_PA,     TRUE,  TRUE);  // #GP on guest access
    svm_set_msrpm_bit(msrpm, IA32_FEATURE_CONTROL, TRUE, TRUE);  // #GP on AMD
    for (UINT32 m = IA32_VMX_BASIC; m <= 0x493U; m++)
        svm_set_msrpm_bit(msrpm, m, TRUE, TRUE);

    vcpu->msrpm_pa = va_to_pa((PVOID)vcpu->msrpm_va);

#if USE_PRIVATE_HOST_GDT
    if (!hostgdt_alloc_for_vcpu(vcpu))
        return FALSE;
#endif

    vcpu->npt_cr3         = ept_pml4_pa();
    vcpu->min_exit_cycles = MAXULONG64;
    return TRUE;
}

BOOLEAN
svm_init(VOID)
{
    g_cpu_count     = hv_total_processor_count();
    g_vcpu_capacity = hv_max_processor_count();
    if (!g_cpu_count || !g_vcpu_capacity)
        return FALSE;

    g_vcpu = (VIRTUAL_MACHINE_STATE *)hv_pool_alloc(sizeof(VIRTUAL_MACHINE_STATE) * g_vcpu_capacity);
    if (!g_vcpu)
        return FALSE;
    RtlZeroMemory(g_vcpu, sizeof(VIRTUAL_MACHINE_STATE) * g_vcpu_capacity);

    if (!svm_check_support())
        return FALSE;

    if (!logbuf_init())
        return FALSE;

#if STEALTH_CPUID_CACHING
    stealth_init_cpuid_cache();
#endif

    if (!ept_init())
    {
        HV_LOG("svm: NPT init failed\n");
        return FALSE;
    }

    for (UINT32 i = 0; i < g_vcpu_capacity; i++)
    {
        if (!svm_alloc_vcpu_resources(&g_vcpu[i]))
            return FALSE;
    }

#if USE_PRIVATE_HOST_CR3
    if (!hostcr3_build())
        return FALSE;
#endif

#if USE_PRIVATE_HOST_IDT
    if (!hostidt_build())
        return FALSE;
#endif

    broadcast_virtualize_all();

    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        if (!g_vcpu[i].launched)
        {
            HV_LOG("svm: cpu %u failed to launch, rolling back...\n", i);
            broadcast_terminate_all();
            return FALSE;
        }
    }

    HV_LOG("SVM: all %u logical processors virtualized (capacity=%u)\n", g_cpu_count, g_vcpu_capacity);
    return TRUE;
}

VOID
svm_terminate(VOID)
{
    if (!g_vcpu)
        return;

    for (UINT32 i = 0; i < g_vcpu_capacity; i++)
    {
        VIRTUAL_MACHINE_STATE * vcpu = &g_vcpu[i];

        if (vcpu->vmcb_va)
            hv_free_contiguous((PVOID)vcpu->vmcb_va);
        if (vcpu->hsave_va)
            hv_free_contiguous((PVOID)vcpu->hsave_va);
        if (vcpu->svm_host_vmcb_va)
            hv_free_contiguous((PVOID)vcpu->svm_host_vmcb_va);
        if (vcpu->iopm_va)
            hv_free_contiguous((PVOID)vcpu->iopm_va);
        if (vcpu->msrpm_va)
            hv_free_contiguous((PVOID)vcpu->msrpm_va);
        if (vcpu->vmm_stack_raw)
            hv_free_contiguous(vcpu->vmm_stack_raw);

#if USE_PRIVATE_HOST_GDT
        hostgdt_destroy_for_vcpu(vcpu);
#endif
    }

    ept_destroy();

#if USE_PRIVATE_HOST_CR3
    hostcr3_destroy();
#endif

#if USE_PRIVATE_HOST_IDT
    hostidt_destroy();
#endif

    logbuf_destroy();

    hv_pool_free(g_vcpu);
    g_vcpu          = NULL;
    g_vcpu_capacity = 0;

    HV_LOG("SVM terminated on all processors.\n");
}

const HV_BACKEND g_svm_backend = {
    HV_VENDOR_AMD,
    "AMD-SVM",
    svm_check_support,
    svm_init,
    svm_terminate,
    svm_virtualize_cpu,
    svm_terminate_cpu,
};
