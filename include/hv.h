/*
*   hv.h - master hypervisor header — includes everything needed
*/
#pragma once

//
// windows kernel headers (used only at PASSIVE/DPC level in non-root)
//
#include <ntddk.h>
#include <intrin.h>

#pragma intrinsic(_disable)

#include "ia32.h"
#include "hv_types.h"
#include "hv_ioctl.h"
#include "asm_prototypes.h"
#include "stealth.h"
#include "win_compat.h"
#include "cpuinfo.h"
#include "svm.h"
#include "hv_backend.h"

//
// logging macro — non-root ONLY. NEVER invoke from VMX-root / SVM host mode.
//
#ifndef HV_DEBUG_LOG
#if DBG
#define HV_DEBUG_LOG 1
#else
#define HV_DEBUG_LOG 0
#endif
#endif

#if HV_DEBUG_LOG
#define HV_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[hv] " fmt, ##__VA_ARGS__)
#else
#define HV_LOG(fmt, ...) ((VOID)0)
#endif

UINT64 va_to_pa(PVOID va);
PVOID  pa_to_va(UINT64 pa);
UINT64 get_system_cr3(VOID);

//
// private host page tables (hostcr3.c)
//
BOOLEAN hostcr3_init(VOID);
BOOLEAN hostcr3_map_range(PVOID va, SIZE_T size, BOOLEAN executable);
BOOLEAN hostcr3_build(VOID);
UINT64  hostcr3_get(VOID);
VOID    hostcr3_destroy(VOID);

//
// private host IDT (hostidt.c)
//
BOOLEAN hostidt_build(VOID);
UINT64  hostidt_get_base(VOID);
VOID    hostidt_destroy(VOID);

//
// per-core private host GDT (hostgdt.c)
//
BOOLEAN hostgdt_alloc_for_vcpu(VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN hostgdt_populate_for_vcpu(VIRTUAL_MACHINE_STATE * vcpu);
VOID    hostgdt_destroy_for_vcpu(VIRTUAL_MACHINE_STATE * vcpu);

//
// segment helpers (util.c)
//
VOID segment_get_descriptor(PUCHAR gdt_base, UINT16 selector, VMX_SEGMENT_SELECTOR * result);
VOID segment_fill_vmcs(PVOID gdt_base, UINT32 seg_reg, UINT16 selector);

//
// shared VMX / SVM exit helpers (vmexit_common.c)
//
UINT64 * hv_gpr_ptr(PGUEST_REGS regs, UINT32 idx);
VOID     hv_common_handle_cpuid(PGUEST_REGS regs, BOOLEAN is_amd);
BOOLEAN  hv_common_handle_xsetbv(PGUEST_REGS regs);
BOOLEAN  hv_common_check_vmcall_auth(PGUEST_REGS regs, UINT8 cpl);
BOOLEAN  hv_common_is_synthetic_msr(UINT32 msr);
BOOLEAN  hv_common_validate_cr0(UINT64 val);
BOOLEAN  hv_common_validate_cr3(UINT64 val);
BOOLEAN  hv_common_validate_cr4(UINT64 val);

//
// Intel VMX backend (vmx.c)
//
BOOLEAN vmx_check_support(VOID);
BOOLEAN vmx_init(VOID);
VOID    vmx_terminate(VOID);

BOOLEAN vmx_virtualize_cpu(PVOID guest_stack);
BOOLEAN vmx_setup_vmcs(VIRTUAL_MACHINE_STATE * vcpu, PVOID guest_stack);

BOOLEAN vmx_alloc_vmxon(VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN vmx_alloc_vmcs(VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN vmx_clear_vmcs(VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN vmx_load_vmcs(VIRTUAL_MACHINE_STATE * vcpu);

UINT32  vmx_adjust_controls(UINT32 requested, UINT32 capability_msr);
VOID    vmx_set_fixed_bits(VOID);
VOID    vmx_vmresume(VOID);
UINT64  vmx_return_rsp_for_vmxoff(VIRTUAL_MACHINE_STATE * vcpu);
UINT64  vmx_return_rip_for_vmxoff(VIRTUAL_MACHINE_STATE * vcpu);
UINT64  vmx_return_rflags_for_vmxoff(VIRTUAL_MACHINE_STATE * vcpu);

//
// AMD SVM backend (svm.c)
//
BOOLEAN svm_check_support(VOID);
BOOLEAN svm_init(VOID);
VOID    svm_terminate(VOID);
BOOLEAN svm_virtualize_cpu(PVOID guest_stack);
VOID    svm_terminate_cpu(VOID);
BOOLEAN svm_exit_handler(PGUEST_REGS regs, VIRTUAL_MACHINE_STATE * vcpu);
UINT64  svm_return_rsp_for_off(VIRTUAL_MACHINE_STATE * vcpu);
UINT64  svm_return_rip_for_off(VIRTUAL_MACHINE_STATE * vcpu);
UINT64  svm_return_rflags_for_off(VIRTUAL_MACHINE_STATE * vcpu);

//
// EPT / NPT (ept.c)
//
BOOLEAN ept_check_features(VOID);
BOOLEAN ept_build_mtrr_map(VOID);
BOOLEAN ept_init(VOID);
VOID    ept_destroy(VOID);
UINT64  ept_pml4_pa(VOID);
BOOLEAN ept_is_npt_mode(VOID);
UINT8   ept_get_memory_type(SIZE_T pfn, BOOLEAN is_large_page);
BOOLEAN ept_valid_for_large_page(SIZE_T pfn);
BOOLEAN ept_valid_for_1gb_page(SIZE_T pfn1gb);
BOOLEAN ept_handle_dynamic_mmio(UINT64 gpa);
BOOLEAN ept_map_into_hostcr3(VOID);

//
// EPT / NPT 4KB watchpoints (ept.c)
//
BOOLEAN ept_add_watchpoint(UINT64 phys_addr, UINT32 flags);
BOOLEAN ept_remove_watchpoint(UINT64 phys_addr);
INT32   ept_find_watchpoint_root(UINT64 gpa);
VOID    ept_watchpoint_disarm_root(UINT32 idx);
VOID    ept_watchpoint_rearm_root(UINT32 idx);

//
// lock-free root-mode ring-buffer logger (logbuf.c)
//
BOOLEAN logbuf_init(VOID);
VOID    logbuf_destroy(VOID);
BOOLEAN logbuf_map_into_hostcr3(VOID);
VOID    logbuf_push_root(UINT32 cpu, UINT32 event_type, UINT64 arg1, UINT64 arg2);
UINT32  logbuf_drain(PHV_LOG_ENTRY out_entries, UINT32 max_entries);

//
// dynamic MSR tracing helper (vmx.c / svm.c)
//
BOOLEAN hv_set_msr_trace(UINT32 msr, BOOLEAN trace_read, BOOLEAN trace_write);
BOOLEAN hv_is_msr_traced(UINT32 msr, BOOLEAN is_write);

PEPT_PML1_ENTRY ept_get_pml1(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr);
PEPT_PML2_ENTRY ept_get_pml2(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr);
BOOLEAN ept_split_large_page(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr);

VOID ept_invept_single(EPT_POINTER ept_ptr);
VOID ept_invept_all(VOID);
VOID vpid_invvpid_single(UINT16 vpid);

BOOLEAN vmexit_handler(PGUEST_REGS regs, VIRTUAL_MACHINE_STATE * vcpu);

//
// exit sub-handlers (vmexit.c)
//
VOID vmexit_handle_cpuid(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_msr_read(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_msr_write(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_mov_cr(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_mov_dr(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_ept_violation(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_vmcall(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_triple_fault(VIRTUAL_MACHINE_STATE * vcpu);

//
// event injection helpers (events.c)
//
VOID vmexit_inject_gp(VOID);
VOID vmexit_inject_ud(VOID);
VOID vmexit_inject_df(VOID);
VOID vmexit_inject_interrupt(UINT32 vector);
VOID vmexit_inject_bp(VOID);
VOID vmexit_inject_pf(UINT32 error_code, UINT64 fault_addr);

VOID broadcast_virtualize_all(VOID);
VOID broadcast_terminate_all(VOID);

extern BOOLEAN g_hv_active;     // TRUE once every logical processor is virtualized

NTSTATUS DriverEntry(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registry_path);
VOID     DriverUnload(PDRIVER_OBJECT driver_obj);
