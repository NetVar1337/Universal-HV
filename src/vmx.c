/*
*   vmx.c - Intel VT-x (VMX) initialization, VMCS setup, and lifecycle management
*/
#include "hv.h"

BOOLEAN
vmx_check_support(VOID)
{
    return (g_cpu.vendor == HV_VENDOR_INTEL && g_cpu.vmx_usable) ? TRUE : FALSE;
}

UINT32
vmx_adjust_controls(UINT32 requested, UINT32 capability_msr)
{
    MSR msr_val = {0};
    msr_val.Flags = __readmsr(capability_msr);

    //
    // bit == 0 in high word -> must be zero
    // bit == 1 in low word  -> must be one
    //
    requested &= msr_val.Fields.High;
    requested |= msr_val.Fields.Low;
    return requested;
}

VOID
vmx_set_fixed_bits(VOID)
{
    CR_FIXED fixed = {0};
    CR4      cr4   = {0};
    CR0      cr0   = {0};

    fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
    cr0.AsUInt  = __readcr0();
    cr0.AsUInt |= fixed.Fields.Low;
    fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
    cr0.AsUInt &= fixed.Fields.Low;
    __writecr0(cr0.AsUInt);

    fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED0);
    cr4.AsUInt  = __readcr4();
    cr4.AsUInt |= fixed.Fields.Low;
    fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED1);
    cr4.AsUInt &= fixed.Fields.Low;
    __writecr4(cr4.AsUInt);
}

BOOLEAN
vmx_alloc_vmxon(VIRTUAL_MACHINE_STATE * vcpu)
{
    IA32_VMX_BASIC_REGISTER vmx_basic = {0};
    UINT8 *                 vmxon_region;
    UINT64                  phys_addr;
    UINT64                  aligned_va;
    UINT64                  aligned_pa;

    vmxon_region = (UINT8 *)hv_alloc_contiguous(2 * VMXON_SIZE + ALIGNMENT_PAGE_SIZE);
    if (!vmxon_region)
        return FALSE;

    RtlZeroMemory(vmxon_region, 2 * VMXON_SIZE + ALIGNMENT_PAGE_SIZE);

    phys_addr  = va_to_pa(vmxon_region);
    aligned_va = (UINT64)(((ULONG_PTR)vmxon_region + ALIGNMENT_PAGE_SIZE - 1) & ~(ULONG_PTR)(ALIGNMENT_PAGE_SIZE - 1));
    aligned_pa = (UINT64)((phys_addr + ALIGNMENT_PAGE_SIZE - 1) & ~(UINT64)(ALIGNMENT_PAGE_SIZE - 1));

    vmx_basic.AsUInt       = __readmsr(IA32_VMX_BASIC);
    *(UINT32 *)aligned_va  = (UINT32)vmx_basic.VmcsRevisionId;

    vcpu->vmxon_pa = aligned_pa;
    vcpu->vmxon_va = (UINT64)vmxon_region;
    return TRUE;
}

BOOLEAN
vmx_alloc_vmcs(VIRTUAL_MACHINE_STATE * vcpu)
{
    IA32_VMX_BASIC_REGISTER vmx_basic = {0};
    UINT8 *                 vmcs_region;
    UINT64                  phys_addr;
    UINT64                  aligned_va;
    UINT64                  aligned_pa;

    vmcs_region = (UINT8 *)hv_alloc_contiguous(2 * VMCS_SIZE + ALIGNMENT_PAGE_SIZE);
    if (!vmcs_region)
        return FALSE;

    RtlZeroMemory(vmcs_region, 2 * VMCS_SIZE + ALIGNMENT_PAGE_SIZE);

    phys_addr  = va_to_pa(vmcs_region);
    aligned_va = (UINT64)(((ULONG_PTR)vmcs_region + ALIGNMENT_PAGE_SIZE - 1) & ~(ULONG_PTR)(ALIGNMENT_PAGE_SIZE - 1));
    aligned_pa = (UINT64)((phys_addr + ALIGNMENT_PAGE_SIZE - 1) & ~(UINT64)(ALIGNMENT_PAGE_SIZE - 1));

    vmx_basic.AsUInt      = __readmsr(IA32_VMX_BASIC);
    *(UINT32 *)aligned_va = (UINT32)vmx_basic.VmcsRevisionId;

    vcpu->vmcs_pa = aligned_pa;
    vcpu->vmcs_va = (UINT64)vmcs_region;
    return TRUE;
}

BOOLEAN
vmx_clear_vmcs(VIRTUAL_MACHINE_STATE * vcpu)
{
    if (__vmx_vmclear(&vcpu->vmcs_pa))
    {
        __vmx_off();
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
vmx_load_vmcs(VIRTUAL_MACHINE_STATE * vcpu)
{
    if (__vmx_vmptrld(&vcpu->vmcs_pa))
    {
        __vmx_off();
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
vmx_setup_vmcs(VIRTUAL_MACHINE_STATE * vcpu, PVOID guest_stack)
{
    UINT32                  pri_proc;
    UINT32                  sec_proc;
    UINT64                  gdt_base;
    IA32_VMX_BASIC_REGISTER vmx_basic = {0};
    VMX_SEGMENT_SELECTOR    seg_sel   = {0};

    vmx_basic.AsUInt = __readmsr(IA32_VMX_BASIC);

    //
    // mask RPL and TI bits (bits 0-2) per Intel SDM
    //
    __vmx_vmwrite(VMCS_HOST_ES_SELECTOR, asm_get_es() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_CS_SELECTOR, asm_get_cs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_SS_SELECTOR, asm_get_ss() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_DS_SELECTOR, asm_get_ds() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_FS_SELECTOR, asm_get_fs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_GS_SELECTOR, asm_get_gs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_TR_SELECTOR, asm_get_tr() & 0xF8);

    __vmx_vmwrite(VMCS_GUEST_VMCS_LINK_POINTER, ~0ULL);
    __vmx_vmwrite(VMCS_GUEST_DEBUGCTL, __readmsr(IA32_DEBUGCTL));

    __vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, 0);
    __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, 0);
    __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, 0);
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);

    gdt_base = asm_get_gdt_base();

    //
    // save per-core original IDT/GDT/TR (Windows 10/11 maintain per-core IDTs)
    //
    vcpu->original_idt_base  = asm_get_idt_base();
    vcpu->original_idt_limit = asm_get_idt_limit();

#if USE_PRIVATE_HOST_GDT
    if (!hostgdt_populate_for_vcpu(vcpu))
        return FALSE;
#else
    vcpu->original_gdt_base    = gdt_base;
    vcpu->original_gdt_limit   = asm_get_gdt_limit();
    vcpu->original_tr_selector = asm_get_tr();
#endif

    segment_fill_vmcs((PVOID)gdt_base, ES,   asm_get_es());
    segment_fill_vmcs((PVOID)gdt_base, CS,   asm_get_cs());
    segment_fill_vmcs((PVOID)gdt_base, SS,   asm_get_ss());
    segment_fill_vmcs((PVOID)gdt_base, DS,   asm_get_ds());
    segment_fill_vmcs((PVOID)gdt_base, FS,   asm_get_fs());
    segment_fill_vmcs((PVOID)gdt_base, GS,   asm_get_gs());
    segment_fill_vmcs((PVOID)gdt_base, LDTR, asm_get_ldtr());
    segment_fill_vmcs((PVOID)gdt_base, TR,   asm_get_tr());

    __vmx_vmwrite(VMCS_GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
    __vmx_vmwrite(VMCS_GUEST_GS_BASE, __readmsr(IA32_GS_BASE));

    UINT32 pri_msr = vmx_basic.VmxControls ? IA32_VMX_TRUE_PROCBASED_CTLS : IA32_VMX_PROCBASED_CTLS;
    {
        MSR pri_cap = {0};
        pri_cap.Flags = __readmsr(pri_msr);
        vcpu->cr8_load_exiting_forced = !!(pri_cap.Fields.Low & CPU_BASED_VM_EXEC_CTRL_CR8_LOAD_EXITING);
    }

    pri_proc = vmx_adjust_controls(
        CPU_BASED_VM_EXEC_CTRL_USE_TSC_OFFSETTING |
        CPU_BASED_VM_EXEC_CTRL_USE_MSR_BITMAPS |
        CPU_BASED_VM_EXEC_CTRL_USE_IO_BITMAPS |
        CPU_BASED_VM_EXEC_CTRL_ACTIVATE_SECONDARY_CONTROLS,
        pri_msr);

    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pri_proc);

    vcpu->mov_dr_exiting = !!(pri_proc & CPU_BASED_VM_EXEC_CTRL_MOV_DR_EXITING);
    vcpu->guest_cr8      = (UINT8)__readcr8();

    sec_proc = vmx_adjust_controls(
        CPU_BASED_VM_EXEC_CTRL2_ENABLE_EPT |
        CPU_BASED_VM_EXEC_CTRL2_ENABLE_VPID |
        CPU_BASED_VM_EXEC_CTRL2_RDTSCP |
        CPU_BASED_VM_EXEC_CTRL2_ENABLE_INVPCID |
        CPU_BASED_VM_EXEC_CTRL2_ENABLE_XSAVES |
        CPU_BASED_VM_EXEC_CTRL2_ENABLE_USER_WAIT_PAUSE,
        IA32_VMX_PROCBASED_CTLS2);

    g_ept->vpid_enabled = !!(sec_proc & CPU_BASED_VM_EXEC_CTRL2_ENABLE_VPID);

    __vmx_vmwrite(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, sec_proc);

    //
    // SDM 26.2.1.1: if ENABLE_XSAVES is set, XSS-exiting bitmap MUST point to
    // a valid zeroed 4KB page (leaving it 0 points at physical address 0 / IVT!).
    //
    if (sec_proc & CPU_BASED_VM_EXEC_CTRL2_ENABLE_XSAVES)
    {
        __vmx_vmwrite(VMCS_CTRL_XSS_EXITING_BITMAP, vcpu->xss_bitmap_pa);
    }

    UINT32 pin_ctrl = vmx_adjust_controls(
        PIN_BASED_VM_EXEC_CTRL_NMI_EXITING |
        PIN_BASED_VM_EXEC_CTRL_VIRTUAL_NMI,
        vmx_basic.VmxControls ? IA32_VMX_TRUE_PINBASED_CTLS : IA32_VMX_PINBASED_CTLS);

    if (pin_ctrl & PIN_BASED_VM_EXEC_CTRL_VIRTUAL_NMI)
        pin_ctrl |= PIN_BASED_VM_EXEC_CTRL_NMI_EXITING;

    __vmx_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, pin_ctrl);

    UINT32 exit_ctrl = vmx_adjust_controls(
        VM_EXIT_CTRL_HOST_ADDRESS_SPACE_SIZE |
        VM_EXIT_CTRL_SAVE_DEBUG_CONTROLS |
        VM_EXIT_CTRL_ACK_INTERRUPT_ON_EXIT,
        vmx_basic.VmxControls ? IA32_VMX_TRUE_EXIT_CTLS : IA32_VMX_EXIT_CTLS);

    __vmx_vmwrite(VMCS_CTRL_PRIMARY_VMEXIT_CONTROLS, exit_ctrl);

    __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS,
                  vmx_adjust_controls(
                      VM_ENTRY_CTRL_IA32E_MODE_GUEST |
                      VM_ENTRY_CTRL_LOAD_DEBUG_CONTROLS,
                      vmx_basic.VmxControls ? IA32_VMX_TRUE_ENTRY_CTLS : IA32_VMX_ENTRY_CTLS));

    __vmx_vmwrite(VMCS_CTRL_CR0_GUEST_HOST_MASK, 0);
    __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, 0);

#if STEALTH_HIDE_CR4_VMXE
    if (g_stealth_enabled)
    {
        __vmx_vmwrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, CR4_VMX_ENABLE_FLAG);
        __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, __readcr4() & ~CR4_VMX_ENABLE_FLAG);
    }
    else
#endif
    {
        __vmx_vmwrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, 0);
        __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, 0);
    }

    __vmx_vmwrite(VMCS_GUEST_CR0, __readcr0());
    __vmx_vmwrite(VMCS_GUEST_CR3, __readcr3());
    __vmx_vmwrite(VMCS_GUEST_CR4, __readcr4());
    __vmx_vmwrite(VMCS_GUEST_DR7, __readdr(7));

    __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_STATE_ACTIVE);
    __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, 0);
    __vmx_vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, 0);

    __vmx_vmwrite(VMCS_HOST_CR0, __readcr0());
    __vmx_vmwrite(VMCS_HOST_CR4, __readcr4());

#if USE_PRIVATE_HOST_CR3
    __vmx_vmwrite(VMCS_HOST_CR3, hostcr3_get());
#else
    __vmx_vmwrite(VMCS_HOST_CR3, get_system_cr3());
#endif

    __vmx_vmwrite(VMCS_GUEST_GDTR_BASE,  gdt_base);
    __vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT, asm_get_gdt_limit());
    __vmx_vmwrite(VMCS_GUEST_IDTR_BASE,  vcpu->original_idt_base);
    __vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT, vcpu->original_idt_limit);
    __vmx_vmwrite(VMCS_GUEST_RFLAGS,     asm_get_rflags());

    __vmx_vmwrite(VMCS_GUEST_SYSENTER_CS,  __readmsr(IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

#if USE_PRIVATE_HOST_GDT
    if (vcpu->host_gdt)
    {
        segment_get_descriptor((PUCHAR)vcpu->host_gdt, asm_get_tr(), &seg_sel);
        __vmx_vmwrite(VMCS_HOST_TR_BASE,   seg_sel.Base);
        __vmx_vmwrite(VMCS_HOST_GDTR_BASE, (UINT64)vcpu->host_gdt);
    }
    else
#endif
    {
        segment_get_descriptor((PUCHAR)gdt_base, asm_get_tr(), &seg_sel);
        __vmx_vmwrite(VMCS_HOST_TR_BASE,   seg_sel.Base);
        __vmx_vmwrite(VMCS_HOST_GDTR_BASE, gdt_base);
    }

#if USE_PRIVATE_HOST_IDT
    if (g_host_idt.initialized)
        __vmx_vmwrite(VMCS_HOST_IDTR_BASE, hostidt_get_base());
    else
#endif
        __vmx_vmwrite(VMCS_HOST_IDTR_BASE, vcpu->original_idt_base);

    __vmx_vmwrite(VMCS_HOST_FS_BASE, __readmsr(IA32_FS_BASE));
    __vmx_vmwrite(VMCS_HOST_GS_BASE, __readmsr(IA32_GS_BASE));

    __vmx_vmwrite(VMCS_HOST_SYSENTER_CS,  __readmsr(IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_HOST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_HOST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

    __vmx_vmwrite(VMCS_CTRL_MSR_BITMAP_ADDRESS,  vcpu->msr_bitmap_pa);
    __vmx_vmwrite(VMCS_CTRL_IO_BITMAP_A_ADDRESS, vcpu->io_bitmap_pa_a);
    __vmx_vmwrite(VMCS_CTRL_IO_BITMAP_B_ADDRESS, vcpu->io_bitmap_pa_b);
    __vmx_vmwrite(VMCS_CTRL_EPT_POINTER,         vcpu->ept_pointer.AsUInt);

    if (g_ept->vpid_enabled)
        __vmx_vmwrite(VIRTUAL_PROCESSOR_ID, VPID_TAG);

    __vmx_vmwrite(VMCS_GUEST_RSP, (UINT64)guest_stack);
    __vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)asm_vmx_restore_state);

    //
    // VMM stack layout (32KB aligned):
    //   [top - 0x08] = vcpu pointer
    //   [top - 0x10] = scratch
    //   [top - 0x18] = per-core host_nmi_pending (zeroed)
    //   [top - 0x20] = HOST_RSP (16-byte aligned)
    //
    UINT64 stack_top = vcpu->vmm_stack + VMM_STACK_SIZE;
    *(PVIRTUAL_MACHINE_STATE *)(stack_top - VMM_STACK_VCPU_OFFSET) = vcpu;
    *(UINT64 *)(stack_top - VMM_STACK_VMCB_OFFSET)                 = 0;
    *(UINT64 *)(stack_top - VMM_STACK_NMI_OFFSET)                  = 0;

    __vmx_vmwrite(VMCS_HOST_RSP, stack_top - VMM_STACK_RSP_OFFSET);
    __vmx_vmwrite(VMCS_HOST_RIP, (UINT64)asm_vmexit_handler);

    return TRUE;
}

BOOLEAN
vmx_virtualize_cpu(PVOID guest_stack)
{
    ULONG                   core       = hv_current_processor_index();
    VIRTUAL_MACHINE_STATE * vcpu       = NULL;
    UINT64                  error_code = 0;

    if (!g_vcpu || core >= g_vcpu_capacity)
        return FALSE;

    vcpu = &g_vcpu[core];
    if (vcpu->launched)
        return TRUE;

    vcpu->proc_index = core;
    vcpu->core_id    = core;
    vcpu->vmxoff.executed = FALSE;

    //
    // IA32_FEATURE_CONTROL is per-logical-processor — ensure VMX outside SMX
    // is unlocked/enabled on THIS core before VMXON.
    //
    if (!cpuinfo_vmx_enable_current_cpu())
    {
        HV_LOG("IA32_FEATURE_CONTROL forbids VMX on core %u\n", core);
        return FALSE;
    }

    asm_enable_vmx();
    vmx_set_fixed_bits();

    if (__vmx_on(&vcpu->vmxon_pa))
    {
        HV_LOG("VMXON failed on core %u\n", core);
        __writecr4(__readcr4() & ~CR4_VMX_ENABLE_FLAG);
        return FALSE;
    }

    if (!vmx_clear_vmcs(vcpu))
    {
        __writecr4(__readcr4() & ~CR4_VMX_ENABLE_FLAG);
        return FALSE;
    }

    if (!vmx_load_vmcs(vcpu))
    {
        __writecr4(__readcr4() & ~CR4_VMX_ENABLE_FLAG);
        return FALSE;
    }

    if (!vmx_setup_vmcs(vcpu, guest_stack))
    {
        HV_LOG("vmx_setup_vmcs failed on core %u\n", core);
        __vmx_off();
        __writecr4(__readcr4() & ~CR4_VMX_ENABLE_FLAG);
        return FALSE;
    }

    vcpu->launched = TRUE;

    __vmx_vmlaunch();

    //
    // only reached if VMLAUNCH failed
    //
    vcpu->launched = FALSE;
    __vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &error_code);
    __vmx_off();
    __writecr4(__readcr4() & ~CR4_VMX_ENABLE_FLAG);

    HV_LOG("VMLAUNCH failed on core %u, error: 0x%llx\n", core, error_code);
    return FALSE;
}

//
// called from AsmVmexitHandler.asm (VMX-root mode — ZERO Windows APIs!).
// if VMRESUME ever fails, record VM_INSTRUCTION_ERROR into g_host_fault_info
// and halt cleanly rather than invoking DbgPrintEx on a private host CR3.
//
VOID
vmx_vmresume(VOID)
{
    __vmx_vmresume();

    UINT64 error_code = 0;
    __vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &error_code);

    if (_InterlockedCompareExchange(&g_host_fault_info.valid, 1, 0) == 0)
    {
        g_host_fault_info.vector     = 0xFE; // synthetic VMRESUME failure marker
        g_host_fault_info.error_code = error_code;
        __vmx_vmread(VMCS_GUEST_RIP, &g_host_fault_info.rip);
        __vmx_vmread(VMCS_GUEST_RSP, &g_host_fault_info.rsp);
        __vmx_vmread(VMCS_GUEST_RFLAGS, &g_host_fault_info.rflags);
    }

    logbuf_push_root(0, HV_LOG_EVT_VMRESUME_FAIL, error_code, 0);

    _disable();
    for (;;)
        __halt();
}

static BOOLEAN
vmx_alloc_vcpu_resources(VIRTUAL_MACHINE_STATE * vcpu)
{
    //
    // 32KB-aligned VMM stack so the host NMI handler can locate stack top from RSP
    //
    vcpu->vmm_stack = (UINT64)hv_alloc_aligned_contiguous(
        VMM_STACK_SIZE, VMM_STACK_SIZE, &vcpu->vmm_stack_raw);
    if (!vcpu->vmm_stack)
        return FALSE;
    RtlZeroMemory((PVOID)vcpu->vmm_stack, VMM_STACK_SIZE);

    //
    // MSR bitmap (4KB contiguous — guaranteed page-aligned under Driver Verifier)
    //
    vcpu->msr_bitmap_va = (UINT64)hv_alloc_contiguous(PAGE_SIZE);
    if (!vcpu->msr_bitmap_va)
        return FALSE;
    RtlZeroMemory((PVOID)vcpu->msr_bitmap_va, PAGE_SIZE);

    // intercept RDMSR(0x10) IA32_TIME_STAMP_COUNTER
    ((PUCHAR)vcpu->msr_bitmap_va)[0x10 / 8] |= (UCHAR)(1U << (0x10 % 8));

    // intercept IA32_FEATURE_CONTROL read+write
    ((PUCHAR)vcpu->msr_bitmap_va)[0x3A / 8]         |= (UCHAR)(1U << (0x3A % 8));
    ((PUCHAR)vcpu->msr_bitmap_va)[0x800 + 0x3A / 8] |= (UCHAR)(1U << (0x3A % 8));

    // intercept VMX capability MSRs (0x480-0x493) read+write
    for (UINT32 msr_idx = 0x480; msr_idx <= 0x493; msr_idx++)
    {
        ((PUCHAR)vcpu->msr_bitmap_va)[msr_idx / 8]         |= (UCHAR)(1U << (msr_idx % 8));
        ((PUCHAR)vcpu->msr_bitmap_va)[0x800 + msr_idx / 8] |= (UCHAR)(1U << (msr_idx % 8));
    }
    vcpu->msr_bitmap_pa = va_to_pa((PVOID)vcpu->msr_bitmap_va);

    //
    // I/O Bitmap A (ports 0x0000 - 0x7FFF)
    //
    vcpu->io_bitmap_va_a = (UINT64)hv_alloc_contiguous(PAGE_SIZE);
    if (!vcpu->io_bitmap_va_a)
        return FALSE;
    RtlZeroMemory((PVOID)vcpu->io_bitmap_va_a, PAGE_SIZE);
    vcpu->io_bitmap_pa_a = va_to_pa((PVOID)vcpu->io_bitmap_va_a);

    //
    // I/O Bitmap B (ports 0x8000 - 0xFFFF)
    //
    vcpu->io_bitmap_va_b = (UINT64)hv_alloc_contiguous(PAGE_SIZE);
    if (!vcpu->io_bitmap_va_b)
        return FALSE;
    RtlZeroMemory((PVOID)vcpu->io_bitmap_va_b, PAGE_SIZE);
    vcpu->io_bitmap_pa_b = va_to_pa((PVOID)vcpu->io_bitmap_va_b);

    //
    // XSS-exiting bitmap (zeroed 4KB contiguous page required for ENABLE_XSAVES)
    //
    vcpu->xss_bitmap_va = (UINT64)hv_alloc_contiguous(PAGE_SIZE);
    if (!vcpu->xss_bitmap_va)
        return FALSE;
    RtlZeroMemory((PVOID)vcpu->xss_bitmap_va, PAGE_SIZE);
    vcpu->xss_bitmap_pa = va_to_pa((PVOID)vcpu->xss_bitmap_va);

#if USE_PRIVATE_HOST_GDT
    //
    // pre-allocate private host GDT BEFORE hostcr3_build() so it is mapped!
    //
    if (!hostgdt_alloc_for_vcpu(vcpu))
        return FALSE;
#endif

    if (!vmx_alloc_vmxon(vcpu))
        return FALSE;

    if (!vmx_alloc_vmcs(vcpu))
        return FALSE;

    vcpu->min_exit_cycles = MAXULONG64;
    return TRUE;
}

BOOLEAN
vmx_init(VOID)
{
    g_cpu_count     = hv_total_processor_count();
    g_vcpu_capacity = hv_max_processor_count();
    if (!g_cpu_count || !g_vcpu_capacity)
        return FALSE;

    g_vcpu = (VIRTUAL_MACHINE_STATE *)hv_pool_alloc(sizeof(VIRTUAL_MACHINE_STATE) * g_vcpu_capacity);
    if (!g_vcpu)
        return FALSE;
    RtlZeroMemory(g_vcpu, sizeof(VIRTUAL_MACHINE_STATE) * g_vcpu_capacity);

    if (!vmx_check_support())
    {
        HV_LOG("VMX not supported!\n");
        return FALSE;
    }

    if (!logbuf_init())
        return FALSE;

#if STEALTH_CPUID_CACHING
    stealth_init_cpuid_cache();
#endif

    if (!ept_init())
    {
        HV_LOG("EPT initialization failed!\n");
        return FALSE;
    }

    for (UINT32 i = 0; i < g_vcpu_capacity; i++)
    {
        if (!vmx_alloc_vcpu_resources(&g_vcpu[i]))
            return FALSE;
    }

    //
    // build minimal private host page tables AFTER all allocations (including
    // per-core host_gdt, VMM stacks, EPT tables, and root log ring).
    //
#if USE_PRIVATE_HOST_CR3
    if (!hostcr3_build())
    {
        HV_LOG("Host CR3 build failed!\n");
        return FALSE;
    }
#endif

#if USE_PRIVATE_HOST_IDT
    if (!hostidt_build())
    {
        HV_LOG("Host IDT build failed!\n");
        return FALSE;
    }
#endif

    broadcast_virtualize_all();

    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        if (!g_vcpu[i].launched)
        {
            HV_LOG("Core %u failed to launch! Rolling back launched cores...\n", i);
            broadcast_terminate_all();
            return FALSE;
        }
    }

    HV_LOG("All %u cores virtualized successfully (capacity=%u)!\n", g_cpu_count, g_vcpu_capacity);
    return TRUE;
}

VOID
vmx_terminate(VOID)
{
    if (!g_vcpu)
        return;

    for (UINT32 i = 0; i < g_vcpu_capacity; i++)
    {
        VIRTUAL_MACHINE_STATE * vcpu = &g_vcpu[i];

        if (vcpu->vmxon_va)
            hv_free_contiguous((PVOID)vcpu->vmxon_va);
        if (vcpu->vmcs_va)
            hv_free_contiguous((PVOID)vcpu->vmcs_va);
        if (vcpu->vmm_stack_raw)
            hv_free_contiguous(vcpu->vmm_stack_raw);
        if (vcpu->msr_bitmap_va)
            hv_free_contiguous((PVOID)vcpu->msr_bitmap_va);
        if (vcpu->io_bitmap_va_a)
            hv_free_contiguous((PVOID)vcpu->io_bitmap_va_a);
        if (vcpu->io_bitmap_va_b)
            hv_free_contiguous((PVOID)vcpu->io_bitmap_va_b);
        if (vcpu->xss_bitmap_va)
            hv_free_contiguous((PVOID)vcpu->xss_bitmap_va);

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

    HV_LOG("VMX terminated on all cores.\n");
}

VOID
vmx_terminate_cpu(VOID)
{
    asm_vmx_vmcall(VMCALL_VMXOFF, 0, 0, 0);
}

const HV_BACKEND g_vmx_backend = {
    HV_VENDOR_INTEL,
    "Intel-VMX",
    vmx_check_support,
    vmx_init,
    vmx_terminate,
    vmx_virtualize_cpu,
    vmx_terminate_cpu,
};
