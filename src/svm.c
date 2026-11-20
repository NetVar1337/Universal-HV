/*
*   svm.c - AMD SVM (AMD-V) backend
*
*   virtualizes the already-running Windows x64 OS on AMD CPUs using the
*   VMCB/VMRUN mechanism. mirrors the VMX backend (vmx.c/vmexit.c):
*   same intercepted operations (CPUID, MSR, CR0/3/4/8, DR0-7, VMMCALL,
*   XSETBV, INVD/WBINVD, NPF), same shared identity-mapped NPT, same private
*   host GDT/IDT/CR3 and stealth options.
*
*   differences vs VMX that are handled here:
*     - EFER.SVME instead of CR4.VMXE; VM_HSAVE_PA host save area
*     - ASID instead of VPID; NPT (nested_cr3) instead of EPT pointer
*     - TPR lives in VMCB int_ctl.V_TPR instead of CR8
*     - no way to fully "leave" SVM from inside the VMRUN loop: the
*       shutdown VMMCALL clears all intercepts + disables NP so the vCPU
*       resumes natively and never exits again (documented limitation).
*/
#include "hv.h"

static __forceinline UINT64 *
svm_gpr_ptr(PGUEST_REGS regs, UINT32 idx)
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
svm_fill_segment(PVMCB vmcb, PSVM_SEGMENT dest, UINT64 gdt_base, UINT16 selector)
{
    VMX_SEGMENT_SELECTOR seg = {0};

    UNREFERENCED_PARAMETER(vmcb);

    segment_get_descriptor((PUCHAR)gdt_base, selector, &seg);

    dest->Selector = selector;
    dest->Attrib   = (selector == 0) ? 0 : (UINT16)(seg.Attributes.AsUInt & 0xFFFF);
    dest->Limit    = seg.Limit;
    dest->Base     = seg.Base;
}

/*
*   CPUID — same stealth policy as the VMX backend, plus hiding the AMD SVM
*   leaf (0x8000000A) and the SVM capability bit (CPUID.80000001:ECX[2]).
*/
static VOID
svm_handle_cpuid(PVMCB vmcb, VIRTUAL_MACHINE_STATE * vcpu, PGUEST_REGS regs)
{
    INT32  cpu_info[4] = {0};
    UINT32 leaf    = (UINT32)regs->rax;
    UINT32 subleaf = (UINT32)regs->rcx;

    UNREFERENCED_PARAMETER(vmcb);

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
            if (leaf == 1)
                cpu_info[2] &= ~(1 << 31);              // hypervisor present bit

            if (leaf == CPUID_EXT_FEATURES)
                cpu_info[2] &= ~(1 << CPUID_SVM_BIT);   // hide SVM capability

            if (leaf == CPUID_SVM_INFO)
            {
                //
                // bare metal with SVM firmware-disabled returns zeros for
                // this leaf; hide the hypervisor's SVM info entirely.
                //
                cpu_info[0] = cpu_info[1] = cpu_info[2] = cpu_info[3] = 0;
            }
        }
    }

    regs->rax = (UINT64)(UINT32)cpu_info[0];
    regs->rbx = (UINT64)(UINT32)cpu_info[1];
    regs->rcx = (UINT64)(UINT32)cpu_info[2];
    regs->rdx = (UINT64)(UINT32)cpu_info[3];

    UNREFERENCED_PARAMETER(vcpu);
}

/*
*   MSR — INTERCEPT_MSR_PROT sends every guest RDMSR/WRMSR here.
*   exit_info1 bit 0: 0 = RDMSR, 1 = WRMSR. MSR number is in guest RCX.
*
*   since host == guest (type-2), forwarding architectural MSRs to the
*   hardware is semantically correct; synthetic/intel-only MSRs get #GP
*   exactly like bare metal, and EFER.SVME is hidden from the guest.
*/
static VOID
svm_handle_msr(PVMCB vmcb, VIRTUAL_MACHINE_STATE * vcpu, PGUEST_REGS regs, BOOLEAN is_write, BOOLEAN * advance)
{
    UINT32 msr = (UINT32)(regs->rcx & 0xFFFFFFFF);
    UINT64 value = ((UINT64)(UINT32)regs->rdx << 32) | (UINT32)regs->rax;

    UNREFERENCED_PARAMETER(vcpu);

    //
    // hypervisor synthetic MSRs and Intel-only MSRs -> #GP like bare AMD metal
    //
    if ((msr >= 0x40000000 && msr <= 0x4FFFFFFF) ||
        (msr >= IA32_VMX_BASIC && msr <= 0x493) ||
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
            // guest EFER must never clear SVME while the hypervisor is
            // loaded; keep the host's SVME=1 and shadow the rest.
            //
            __writemsr(MSR_EFER, value | EFER_SVME);
            vmcb->Save.Efer = value & ~EFER_SVME;
            break;

        default:
            if ((msr <= 0x00001FFF) || (msr >= 0xC0000000 && msr <= 0xC0001FFF))
                __writemsr(msr, value);
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
        UINT64 result;

        switch (msr)
        {
        case 0x10:  // IA32_TIME_STAMP_COUNTER — apply TSC offset manually
        {
            UINT64 tsc_offset = svm_ctrl_read(vmcb, VMCB_CTRL_TSC_OFFSET);
            result = (UINT64)((INT64)__rdtsc() + (INT64)tsc_offset);
            break;
        }

        case MSR_EFER:
            result = __readmsr(MSR_EFER) & ~EFER_SVME;   // hide SVME from guest
            break;

        default:
            if ((msr <= 0x00001FFF) || (msr >= 0xC0000000 && msr <= 0xC0001FFF))
                result = __readmsr(msr);
            else
            {
                svm_inject_gp(vmcb);
                *advance = FALSE;
                return;
            }
            break;
        }

        regs->rax = result & 0xFFFFFFFF;
        regs->rdx = result >> 32;
    }
}

static VOID
svm_handle_cr(PVMCB vmcb, VIRTUAL_MACHINE_STATE * vcpu, PGUEST_REGS regs, UINT64 exit_code, UINT64 info1)
{
    UINT32   gpr = (UINT32)(info1 & SVM_EXITINFO_REG_MASK);
    UINT64 * reg_ptr = svm_gpr_ptr(regs, gpr);
    BOOLEAN  is_write = (exit_code >= SVM_EXIT_WRITE_CR0 && exit_code <= SVM_EXIT_WRITE_CR8);
    UINT32   cr;

    switch (exit_code)
    {
    case SVM_EXIT_READ_CR0:  case SVM_EXIT_WRITE_CR0:  cr = 0; break;
    case SVM_EXIT_READ_CR3:  case SVM_EXIT_WRITE_CR3:  cr = 3; break;
    case SVM_EXIT_READ_CR4:  case SVM_EXIT_WRITE_CR4:  cr = 4; break;
    case SVM_EXIT_READ_CR8:  case SVM_EXIT_WRITE_CR8:  cr = 8; break;
    default: return;
    }

    if (is_write)
    {
        UINT64 val = *reg_ptr;
        switch (cr)
        {
        case 0:
            vmcb->Save.Cr0 = val;
            break;
        case 3:
        {
            BOOLEAN no_flush = (val >> 63) & 1;     // PCID no-invalidate bit
            vmcb->Save.Cr3 = val & ~(1ULL << 63);
            if (!no_flush)
                svm_ctrl_write32(vmcb, VMCB_CTRL_TLB_CTL, SVM_TLB_FLUSH_ASID);
            break;
        }
        case 4:
            vmcb->Save.Cr4 = val;
            break;
        case 8:
            vcpu->guest_cr8 = (UINT8)(val & 0xF);
            {
                UINT32 ic = (UINT32)svm_ctrl_read(vmcb, VMCB_CTRL_INT_CTL);
                ic = (ic & ~SVM_V_TPR_MASK) | vcpu->guest_cr8;
                svm_ctrl_write32(vmcb, VMCB_CTRL_INT_CTL, ic);
            }
            break;
        }
    }
    else
    {
        switch (cr)
        {
        case 0: *reg_ptr = vmcb->Save.Cr0; break;
        case 3: *reg_ptr = vmcb->Save.Cr3; break;
        case 4: *reg_ptr = vmcb->Save.Cr4; break;
        case 8: *reg_ptr = vcpu->guest_cr8; break;
        }
    }
}

static VOID
svm_handle_dr(PVMCB vmcb, PGUEST_REGS regs, UINT64 exit_code, UINT64 info1)
{
    UINT32 gpr = (UINT32)(info1 & SVM_EXITINFO_REG_MASK);
    UINT64 * reg_ptr = svm_gpr_ptr(regs, gpr);
    UINT32 dr;
    BOOLEAN is_write;

    UNREFERENCED_PARAMETER(vmcb);

    if (exit_code >= SVM_EXIT_WRITE_DR0 && exit_code <= SVM_EXIT_WRITE_DR7)
    {
        is_write = TRUE;
        dr = (UINT32)(exit_code - SVM_EXIT_WRITE_DR0);
    }
    else
    {
        is_write = FALSE;
        dr = (UINT32)(exit_code - SVM_EXIT_READ_DR0);
    }

    //
    // DR4/DR5 alias DR6/DR7 when CR4.DE=0, #UD when CR4.DE=1
    //
    if (dr == 4 || dr == 5)
    {
        if (vmcb->Save.Cr4 & (1ULL << 3))
        {
            svm_inject_ud(vmcb);
            return;
        }
        dr = (dr == 4) ? 6 : 7;
    }

    //
    // host and guest are the same OS (type-2): DR0-3 are not part of the
    // VMCB, so forward directly to the hardware debug registers.
    //
    if (is_write)
        __writedr(dr, *reg_ptr);
    else
        *reg_ptr = __readdr(dr);
}

static VOID
svm_handle_vmmcall(PVMCB vmcb, VIRTUAL_MACHINE_STATE * vcpu, PGUEST_REGS regs)
{
    //
    // reject VMMCALL from ring 3 — only kernel callers allowed
    //
    if (vmcb->Save.Cpl != 0)
    {
        svm_inject_ud(vmcb);
        return;
    }

    if (regs->r10 != 0x48564653ULL ||
        regs->r11 != 0x564d43414c4cULL ||
        regs->r12 != 0x4e4f485950455256ULL)
    {
        svm_inject_ud(vmcb);
        return;
    }

    switch (regs->rcx)
    {
    case VMCALL_TEST:
        regs->rax = (UINT64)STATUS_SUCCESS;
        break;

    case VMCALL_VMXOFF:
        //
        // SVM cannot be fully exited from inside the VMRUN loop (VMRUN
        // itself requires EFER.SVME=1). the equivalent shutdown is to clear
        // every intercept and disable nested paging: the vCPU resumes and
        // never #VMEXITs again, so the driver can safely free all state.
        //
        svm_clear_all_intercepts(vmcb);
        svm_ctrl_write(vmcb, VMCB_CTRL_MISC_CTL, 0);
        svm_ctrl_write32(vmcb, VMCB_CTRL_TLB_CTL, SVM_TLB_FLUSH_ALL_ASID);
        vcpu->svm_off = TRUE;
        regs->rax = (UINT64)STATUS_SUCCESS;
        break;

    default:
        regs->rax = (UINT64)STATUS_UNSUCCESSFUL;
        break;
    }
}

/*
*   svm_exit_handler — C entry from asm_svmexit_handler.
*   always resumes the guest with VMRUN afterwards (returns void; the asm
*   stub performs the VMRUN).
*/
VOID
svm_exit_handler(_Inout_ PGUEST_REGS regs, _In_ VIRTUAL_MACHINE_STATE * vcpu)
{
    PVMCB  vmcb = (PVMCB)vcpu->vmcb_va;
    UINT64 exit_code = svm_ctrl_read(vmcb, VMCB_CTRL_EXIT_CODE);
    UINT64 info1     = svm_ctrl_read(vmcb, VMCB_CTRL_EXIT_INFO1);
    UINT64 info2     = svm_ctrl_read(vmcb, VMCB_CTRL_EXIT_INFO2);
    BOOLEAN advance = TRUE;

    vcpu->regs        = regs;
    vcpu->in_root     = TRUE;
    vcpu->exit_reason = (UINT32)exit_code;
    vcpu->exit_qual   = info2;

    //
    // on #VMEXIT only RIP/RSP/RAX come from the VMCB; the rest of the GPRs
    // are in the pushed register frame. guest RAX lives in save.rax.
    //
    regs->rax     = vmcb->Save.Rax;
    regs->rsp     = vmcb->Save.Rsp;
    vcpu->vmexit_rip = vmcb->Save.Rip;
    vcpu->guest_cr8  = (UINT8)(svm_ctrl_read(vmcb, VMCB_CTRL_INT_CTL) & SVM_V_TPR_MASK);

    switch (exit_code)
    {
    case SVM_EXIT_CPUID:
        svm_handle_cpuid(vmcb, vcpu, regs);
        break;

    case SVM_EXIT_MSR:
        svm_handle_msr(vmcb, vcpu, regs, (info1 & 1) ? TRUE : FALSE, &advance);
        break;

    case SVM_EXIT_READ_CR0: case SVM_EXIT_READ_CR3:
    case SVM_EXIT_READ_CR4: case SVM_EXIT_READ_CR8:
    case SVM_EXIT_WRITE_CR0: case SVM_EXIT_WRITE_CR3:
    case SVM_EXIT_WRITE_CR4: case SVM_EXIT_WRITE_CR8:
        svm_handle_cr(vmcb, vcpu, regs, exit_code, info1);
        break;

    case SVM_EXIT_READ_DR0:  case SVM_EXIT_READ_DR1:
    case SVM_EXIT_READ_DR2:  case SVM_EXIT_READ_DR3:
    case SVM_EXIT_READ_DR4:  case SVM_EXIT_READ_DR5:
    case SVM_EXIT_READ_DR6:  case SVM_EXIT_READ_DR7:
    case SVM_EXIT_WRITE_DR0: case SVM_EXIT_WRITE_DR1:
    case SVM_EXIT_WRITE_DR2: case SVM_EXIT_WRITE_DR3:
    case SVM_EXIT_WRITE_DR4: case SVM_EXIT_WRITE_DR5:
    case SVM_EXIT_WRITE_DR6: case SVM_EXIT_WRITE_DR7:
        svm_handle_dr(vmcb, regs, exit_code, info1);
        break;

    case SVM_EXIT_VMMCALL:
        svm_handle_vmmcall(vmcb, vcpu, regs);
        break;

    //
    // SVM instructions in guest — inject #UD (bare metal behavior)
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
    {
        UINT64 index = regs->rcx;
        UINT64 value = ((UINT64)(UINT32)regs->rdx << 32) | (UINT32)regs->rax;

        if ((index & 0xFFFFFFFF00000000ULL) || (UINT32)index != 0 ||
            !stealth_is_xcr0_valid(value))
        {
            svm_inject_gp(vmcb);
            advance = FALSE;
            break;
        }
        _xsetbv(0, value);
        break;
    }

    case SVM_EXIT_INVD:
    case SVM_EXIT_WBINVD:
        __wbinvd();
        break;

    case SVM_EXIT_NPF:
        //
        // nested page fault: with a full identity map this should never
        // happen; if it does, the guest gets #GP (mirrors the VMX EPT
        // violation path).
        //
        svm_inject_gp(vmcb);
        advance = FALSE;
        break;

    case SVM_EXIT_SHUTDOWN:
        advance = FALSE;
        break;

    default:
        //
        // exceptions/interrupts are not intercepted and are delivered to the
        // guest directly by hardware; anything else here is unexpected.
        //
        DbgPrintEx(0, 0, "[hv] svm: unhandled exit 0x%llx (info1=0x%llx info2=0x%llx)\n",
                 exit_code, info1, info2);
        break;
    }

    //
    // advance guest RIP past the intercepted instruction
    //
    if (advance)
    {
        UINT8 insn_len = *(PUINT8)((PUINT8)vmcb->Control + VMCB_CTRL_INSN_LEN);
        vmcb->Save.Rip += insn_len;
    }

    //
    // write back guest RAX (CPUID/MSR/VMMCALL results)
    //
    vmcb->Save.Rax = regs->rax;

    vcpu->in_root = FALSE;
}

BOOLEAN
svm_check_support(VOID)
{
    if (!cpuinfo_svm_check())
        return FALSE;

    //
    // nested paging is required (no shadow-paging fallback)
    //
    if (!(g_cpu.svm_features & SVM_FEATURE_NP))
    {
        DbgPrintEx(0, 0, "[hv] SVM: nested paging (NPT) not supported on this CPU\n");
        return FALSE;
    }

    if (g_cpu.svm_num_asids < 2)
    {
        DbgPrintEx(0, 0, "[hv] SVM: insufficient ASIDs (%u)\n", g_cpu.svm_num_asids);
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
svm_virtualize_cpu(PVOID guest_stack)
{
    ULONG                   idx  = hv_current_processor_index();
    VIRTUAL_MACHINE_STATE * vcpu = &g_vcpu[idx];
    PVMCB                   vmcb;
    UINT64                  gdt_base;

    vcpu->proc_index = idx;
    vcpu->core_id    = idx;
    vcpu->asid       = 1;

    vmcb = (PVMCB)vcpu->vmcb_va;
    RtlZeroMemory(vmcb, PAGE_SIZE);

    //
    // intercepts
    //
    svm_set_intercept(vmcb, SVM_INT_CR0_READ);
    svm_set_intercept(vmcb, SVM_INT_CR3_READ);
    svm_set_intercept(vmcb, SVM_INT_CR4_READ);
    svm_set_intercept(vmcb, SVM_INT_CR8_READ);
    svm_set_intercept(vmcb, SVM_INT_CR0_WRITE);
    svm_set_intercept(vmcb, SVM_INT_CR3_WRITE);
    svm_set_intercept(vmcb, SVM_INT_CR4_WRITE);
    svm_set_intercept(vmcb, SVM_INT_CR8_WRITE);
    for (UINT32 i = 0; i < 8; i++)
    {
        svm_set_intercept(vmcb, SVM_INT_DR0_READ + i);
        svm_set_intercept(vmcb, SVM_INT_DR0_WRITE + i);
    }
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

    svm_ctrl_write(vmcb, VMCB_CTRL_IOPM_BASE_PA, vcpu->iopm_pa);
    svm_ctrl_write(vmcb, VMCB_CTRL_MSRPM_BASE_PA, vcpu->msrpm_pa);
    svm_ctrl_write(vmcb, VMCB_CTRL_TSC_OFFSET, 0);
    svm_ctrl_write32(vmcb, VMCB_CTRL_ASID, vcpu->asid);
    svm_ctrl_write32(vmcb, VMCB_CTRL_TLB_CTL, SVM_TLB_DO_NOTHING);
    svm_ctrl_write32(vmcb, VMCB_CTRL_INT_CTL, 0);
    svm_ctrl_write32(vmcb, VMCB_CTRL_EVENT_INJ, 0);
    svm_ctrl_write32(vmcb, VMCB_CTRL_EVENT_INJ_ERR, 0);

    //
    // nested paging (shared identity map built by ept_init)
    //
    if (g_ept->npt_supported)
    {
        svm_ctrl_write(vmcb, VMCB_CTRL_MISC_CTL, SVM_MISC_ENABLE_NP);
        svm_ctrl_write(vmcb, VMCB_CTRL_NESTED_CR3, ept_pml4_pa());
    }
    else
    {
        DbgPrintEx(0, 0, "[hv] svm: NPT not available, running without nested paging\n");
    }

    //
    // guest state = current CPU state (type-2: we virtualize the running OS)
    //
    gdt_base = asm_get_gdt_base();
    svm_fill_segment(vmcb, &vmcb->Save.Es,   gdt_base, asm_get_es());
    svm_fill_segment(vmcb, &vmcb->Save.Cs,   gdt_base, asm_get_cs());
    svm_fill_segment(vmcb, &vmcb->Save.Ss,   gdt_base, asm_get_ss());
    svm_fill_segment(vmcb, &vmcb->Save.Ds,   gdt_base, asm_get_ds());
    svm_fill_segment(vmcb, &vmcb->Save.Fs,   gdt_base, asm_get_fs());
    svm_fill_segment(vmcb, &vmcb->Save.Gs,   gdt_base, asm_get_gs());
    svm_fill_segment(vmcb, &vmcb->Save.Ldtr, gdt_base, asm_get_ldtr());
    svm_fill_segment(vmcb, &vmcb->Save.Tr,   gdt_base, asm_get_tr());

    vmcb->Save.Gdtr.Selector = 0;
    vmcb->Save.Gdtr.Attrib   = 0;
    vmcb->Save.Gdtr.Limit    = asm_get_gdt_limit();
    vmcb->Save.Gdtr.Base     = gdt_base;

    vmcb->Save.Idtr.Selector = 0;
    vmcb->Save.Idtr.Attrib   = 0;
    vmcb->Save.Idtr.Limit    = asm_get_idt_limit();
    vmcb->Save.Idtr.Base     = asm_get_idt_base();

    vmcb->Save.Cr0    = __readcr0();
    vmcb->Save.Cr3    = __readcr3();
    vmcb->Save.Cr4    = __readcr4();
    vmcb->Save.Efer   = __readmsr(MSR_EFER) & ~EFER_SVME;   // hide SVME from guest
    vmcb->Save.Rflags = asm_get_rflags();
    vmcb->Save.Rip    = (UINT64)asm_svm_restore_state;
    vmcb->Save.Rsp    = (UINT64)guest_stack;
    vmcb->Save.Rax    = 0;
    vmcb->Save.Cpl    = 0;

    //
    // host save area (HSAVE) — loaded by the CPU on every #VMEXIT
    //
    {
        PSVM_HOST_SAVE_AREA hs = (PSVM_HOST_SAVE_AREA)vcpu->hsave_va;
        PSVM_SEGMENT hseg;

        RtlZeroMemory(hs, PAGE_SIZE);

        hseg = (PSVM_SEGMENT)((PUINT8)hs + SVM_HSAVE_OFF_ES);
        hseg->Selector = asm_get_es();
        hseg = (PSVM_SEGMENT)((PUINT8)hs + SVM_HSAVE_OFF_CS);
        hseg->Selector = asm_get_cs();
        {
            VMX_SEGMENT_SELECTOR seg = {0};
            segment_get_descriptor((PUCHAR)gdt_base, asm_get_cs(), &seg);
            hseg->Attrib = (UINT16)(seg.Attributes.AsUInt & 0xFFFF);
        }
        hseg = (PSVM_SEGMENT)((PUINT8)hs + SVM_HSAVE_OFF_SS);
        hseg->Selector = asm_get_ss();
        {
            VMX_SEGMENT_SELECTOR seg = {0};
            segment_get_descriptor((PUCHAR)gdt_base, asm_get_ss(), &seg);
            hseg->Attrib = (UINT16)(seg.Attributes.AsUInt & 0xFFFF);
        }
        hseg = (PSVM_SEGMENT)((PUINT8)hs + SVM_HSAVE_OFF_DS);
        hseg->Selector = asm_get_ds();

        hseg = (PSVM_SEGMENT)((PUINT8)hs + SVM_HSAVE_OFF_GDTR);
        hseg->Base  = gdt_base;
        hseg->Limit = asm_get_gdt_limit();

        hseg = (PSVM_SEGMENT)((PUINT8)hs + SVM_HSAVE_OFF_IDTR);
#if USE_PRIVATE_HOST_IDT
        if (g_host_idt.initialized)
            hseg->Base = hostidt_get_base();
        else
#endif
            hseg->Base = asm_get_idt_base();
        hseg->Limit = asm_get_idt_limit();

        *(UINT64 *)((PUINT8)hs + SVM_HSAVE_OFF_EFER)   = __readmsr(MSR_EFER) | EFER_SVME;
        *(UINT64 *)((PUINT8)hs + SVM_HSAVE_OFF_CR0)    = __readcr0();
#if USE_PRIVATE_HOST_CR3
        *(UINT64 *)((PUINT8)hs + SVM_HSAVE_OFF_CR3)    = hostcr3_get();
#else
        *(UINT64 *)((PUINT8)hs + SVM_HSAVE_OFF_CR3)    = __readcr3();
#endif
        *(UINT64 *)((PUINT8)hs + SVM_HSAVE_OFF_CR4)    = __readcr4();
        *(UINT64 *)((PUINT8)hs + SVM_HSAVE_OFF_RFLAGS) = asm_get_rflags();
        *(UINT64 *)((PUINT8)hs + SVM_HSAVE_OFF_RIP)    = (UINT64)asm_svmexit_handler;
        *(UINT64 *)((PUINT8)hs + SVM_HSAVE_OFF_RSP)    = vcpu->vmm_stack + VMM_STACK_SIZE - 16;
        *(UINT64 *)((PUINT8)hs + SVM_HSAVE_OFF_RAX)    = 0;
    }

    //
    // vmm stack top: [HOST_RSP+0] = vmcb_pa (for VMRUN), [HOST_RSP+8] = vcpu
    //
    *(UINT64 *)(vcpu->vmm_stack + VMM_STACK_SIZE - 16) = vcpu->vmcb_pa;
    *(PVIRTUAL_MACHINE_STATE *)(vcpu->vmm_stack + VMM_STACK_SIZE - VMM_STACK_VCPU_OFFSET) = vcpu;

    //
    // per-cpu SVM enable: HSAVE PA + EFER.SVME, then VMRUN
    //
    __writemsr(MSR_VM_HSAVE_PA, vcpu->hsave_pa);
    asm_svm_enable();

    vcpu->launched = TRUE;

    asm_svm_vmrun(vcpu->vmcb_pa);

    //
    // reaching here means VMRUN failed (it never returns on success)
    //
    vcpu->launched = FALSE;
    DbgPrintEx(0, 0, "[hv] svm: VMRUN failed on cpu %u\n", idx);
    return FALSE;
}

VOID
svm_terminate_cpu(VOID)
{
    asm_svm_vmcall(VMCALL_VMXOFF, 0, 0, 0);
}

BOOLEAN
svm_init(VOID)
{
    g_cpu_count = hv_total_processor_count();
    if (!g_cpu_count)
        return FALSE;

    g_vcpu = (VIRTUAL_MACHINE_STATE *)hv_pool_alloc(sizeof(VIRTUAL_MACHINE_STATE) * g_cpu_count);
    if (!g_vcpu)
        return FALSE;
    RtlZeroMemory(g_vcpu, sizeof(VIRTUAL_MACHINE_STATE) * g_cpu_count);

    if (!svm_check_support())
        return FALSE;

#if STEALTH_CPUID_CACHING
    stealth_init_cpuid_cache();
#endif

    //
    // shared identity-mapped NPT (same page-table format as EPT)
    //
    if (!ept_init())
    {
        DbgPrintEx(0, 0, "[hv] svm: NPT/EPT init failed\n");
        return FALSE;
    }

    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        VIRTUAL_MACHINE_STATE * vcpu = &g_vcpu[i];

        //
        // contiguous (page-aligned) so HSAVE.rsp is guaranteed 16-byte
        // aligned — the asm exit handler's call alignment depends on it
        //
        vcpu->vmm_stack = (UINT64)hv_alloc_contiguous(VMM_STACK_SIZE);
        if (!vcpu->vmm_stack)
            return FALSE;
        RtlZeroMemory((PVOID)vcpu->vmm_stack, VMM_STACK_SIZE);

        vcpu->vmcb_va = (UINT64)hv_alloc_contiguous(VMCB_SIZE);
        if (!vcpu->vmcb_va)
            return FALSE;
        vcpu->vmcb_pa = va_to_pa((PVOID)vcpu->vmcb_va);

        vcpu->hsave_va = (UINT64)hv_alloc_contiguous(PAGE_SIZE);
        if (!vcpu->hsave_va)
            return FALSE;
        vcpu->hsave_pa = va_to_pa((PVOID)vcpu->hsave_va);

        vcpu->iopm_va = (UINT64)hv_alloc_contiguous(IOPM_SIZE);
        if (!vcpu->iopm_va)
            return FALSE;
        RtlZeroMemory((PVOID)vcpu->iopm_va, IOPM_SIZE);   // all-zero = no IO exits
        vcpu->iopm_pa = va_to_pa((PVOID)vcpu->iopm_va);

        vcpu->msrpm_va = (UINT64)hv_alloc_contiguous(0x2000);
        if (!vcpu->msrpm_va)
            return FALSE;
        RtlZeroMemory((PVOID)vcpu->msrpm_va, 0x2000);
        vcpu->msrpm_pa = va_to_pa((PVOID)vcpu->msrpm_va);

        //
        // shared NPT pointer
        //
        vcpu->npt_cr3 = ept_pml4_pa();
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
            DbgPrintEx(0, 0, "[hv] svm: cpu %u failed to launch\n", i);
            return FALSE;
        }
    }

    DbgPrintEx(0, 0, "[hv] SVM: all %u logical processors virtualized\n", g_cpu_count);
    return TRUE;
}

VOID
svm_terminate(VOID)
{
    if (!g_vcpu)
        return;

    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        VIRTUAL_MACHINE_STATE * vcpu = &g_vcpu[i];

        if (vcpu->vmcb_va)
            hv_free_contiguous((PVOID)vcpu->vmcb_va);
        if (vcpu->hsave_va)
            hv_free_contiguous((PVOID)vcpu->hsave_va);
        if (vcpu->iopm_va)
            hv_free_contiguous((PVOID)vcpu->iopm_va);
        if (vcpu->msrpm_va)
            hv_free_contiguous((PVOID)vcpu->msrpm_va);
        if (vcpu->vmm_stack)
            hv_free_contiguous((PVOID)vcpu->vmm_stack);

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

    hv_pool_free(g_vcpu);
    g_vcpu = NULL;

    DbgPrintEx(0, 0, "[hv] SVM terminated on all processors.\n");
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
