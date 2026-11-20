/*
*   hv_types.h - core hypervisor type definitions — per-vcpu state, ept/npt structures, configs
*   zero windows api dependency in vmx/svm-root mode by design
*/
#pragma once

#include "ia32.h"

#ifndef MAXULONG64
#define MAXULONG64              ((ULONG64)~((ULONG64)0))
#endif

//
// per-VCPU VMM stack layout (32 KB, 32 KB aligned):
//   [vmm_stack + VMM_STACK_SIZE - 0x08] = vcpu pointer
//   [vmm_stack + VMM_STACK_SIZE - 0x10] = vmcb_pa (SVM) / scratch (VMX)
//   [vmm_stack + VMM_STACK_SIZE - 0x18] = per-core host_nmi_pending flag (volatile LONG)
//   [vmm_stack + VMM_STACK_SIZE - 0x20] = initial HOST_RSP (16-byte aligned)
//
// because vmm_stack is aligned to VMM_STACK_SIZE, any host-mode handler
// (including NMI) can locate the top of stack with (RSP | (VMM_STACK_SIZE - 1)).
//
#define VMM_STACK_SIZE          0x8000      // 32 KB per-VCPU VMM stack (power of 2)
#define VMM_STACK_VCPU_OFFSET   0x08
#define VMM_STACK_VMCB_OFFSET   0x10
#define VMM_STACK_NMI_OFFSET    0x18
#define VMM_STACK_RSP_OFFSET    0x20

#define VMXON_SIZE              0x1000
#define VMCS_SIZE               0x1000
#define VMCB_SIZE               0x1000      // SVM VMCB is one 4KB page
#define IOPM_SIZE               0x3000      // SVM I/O permission map (3 pages)
#define MSRPM_SIZE              0x2000      // SVM MSR permission map (8KB)
#define MAX_MTRR_RANGES         256
#define MAX_RAM_RANGES          256
#define EPT_DYN_POOL_PAGES      256         // pre-allocated pages for root-mode MMIO mapping
#define EPT_MAX_TRACKED_PAGES   8192

#define HV_POOL_TAG             'nhpO'

//
// shared VMCALL / VMMCALL authentication signature registers
//
#define HV_VMCALL_SIG_R10       0x48564653ULL           // 'HVFS'
#define HV_VMCALL_SIG_R11       0x564d43414c4cULL       // 'VMCALL'
#define HV_VMCALL_SIG_R12       0x4e4f485950455256ULL   // 'NOHYPERV'

typedef struct _GUEST_REGS {
    UINT64 rax;
    UINT64 rcx;
    UINT64 rdx;
    UINT64 rbx;
    UINT64 rsp;    // placeholder — real RSP read from VMCS/VMCB
    UINT64 rbp;
    UINT64 rsi;
    UINT64 rdi;
    UINT64 r8;
    UINT64 r9;
    UINT64 r10;
    UINT64 r11;
    UINT64 r12;
    UINT64 r13;
    UINT64 r14;
    UINT64 r15;
} GUEST_REGS, *PGUEST_REGS;

typedef struct _VMX_VMXOFF_STATE {
    BOOLEAN executed;
    UINT64  guest_rip;
    UINT64  guest_rsp;
    UINT64  guest_rflags;
    UINT64  guest_cr3;
} VMX_VMXOFF_STATE;

typedef struct _MTRR_RANGE_DESCRIPTOR {
    UINT64  phys_base;
    UINT64  phys_end;   // inclusive
    UINT8   mem_type;
    BOOLEAN fixed;
} MTRR_RANGE_DESCRIPTOR;

typedef struct _RAM_RANGE {
    UINT64 base;
    UINT64 end;         // inclusive
} RAM_RANGE;

//
// tracked physical/virtual page pair — allows root-mode EPT/NPT walks
// without calling MmGetVirtualForPhysical in root mode.
//
typedef struct _VMM_EPT_PAGE {
    PVOID  Va;
    UINT64 Pa;
} VMM_EPT_PAGE, *PVMM_EPT_PAGE;

//
// dynamic EPT (Intel) / NPT (AMD) page table.
//
// PML4_Page is allocated with hv_alloc_contiguous(PAGE_SIZE) so it is strictly
// 4KB physically aligned even under Driver Verifier Special Pool.
// DynPool holds pre-allocated, pre-translated pages so root-mode EPT/NPF
// handlers can lazily map above-4G PCIe BAR MMIO without any Windows API calls.
//
typedef struct _VMM_EPT_PAGE_TABLE {
    PVOID          PML4_Page;                   // 4KB contiguous PML4 table (VA)
    UINT64         PML4_Pa;                     // physical address of PML4_Page
    PVOID          PML3[512];                   // VA of each allocated PML3 table (NULL = absent)

    VMM_EPT_PAGE   Tracked[EPT_MAX_TRACKED_PAGES];
    UINT32         TrackedCount;

    VMM_EPT_PAGE   DynPool[EPT_DYN_POOL_PAGES];
    UINT32         DynPoolCount;
    UINT32         DynPoolUsed;
    volatile LONG  DynLock;
    volatile LONG64 DynMappedCount;
} VMM_EPT_PAGE_TABLE, *PVMM_EPT_PAGE_TABLE;

typedef struct _EPT_STATE {
    MTRR_RANGE_DESCRIPTOR mem_ranges[MAX_MTRR_RANGES];
    UINT32                num_ranges;
    UINT8                 default_type;
    BOOLEAN               ad_supported;
    BOOLEAN               is_npt;               // TRUE on AMD (x86-64 PTE format), FALSE on Intel (EPT)
    UINT8                 npt_pat_index[8];     // maps MEMORY_TYPE_* -> 3-bit (PAT,PCD,PWT) index on AMD
    LIST_ENTRY            hooked_pages;         // reserved for future EPT hooks

    //
    // physical memory map (from MmGetPhysicalMemoryRanges)
    //
    RAM_RANGE             ram_ranges[MAX_RAM_RANGES];
    UINT32                num_ram_ranges;
    UINT8                 maxphyaddr;

    //
    // shared identity-mapped page table (EPT on Intel, NPT on AMD)
    //
    PVMM_EPT_PAGE_TABLE   page_table;

    //
    // INVVPID capability bits (cached from IA32_VMX_EPT_VPID_CAP, Intel)
    //
    BOOLEAN               invvpid_supported;
    BOOLEAN               invvpid_individual_addr;
    BOOLEAN               invvpid_single_context;
    BOOLEAN               invvpid_all_contexts;
    BOOLEAN               invvpid_single_retaining_globals;
    BOOLEAN               vpid_enabled;
    BOOLEAN               npt_supported;
} EPT_STATE, *PEPT_STATE;

typedef struct _VIRTUAL_MACHINE_STATE {

    UINT64 vmxon_va;                    // Intel VMXON raw allocation
    UINT64 vmxon_pa;                    // 4KB aligned PA
    UINT64 vmcs_va;                     // Intel VMCS raw allocation
    UINT64 vmcs_pa;                     // 4KB aligned PA

    UINT64 vmcb_va;                     // AMD guest VMCB (4KB contiguous)
    UINT64 vmcb_pa;
    UINT64 hsave_va;                    // AMD host save area (4KB contiguous)
    UINT64 hsave_pa;
    UINT64 svm_host_vmcb_va;            // AMD host hidden-state VMCB (VMSAVE/VMLOAD)
    UINT64 svm_host_vmcb_pa;
    UINT64 iopm_va;                     // AMD IOPM (3 pages contiguous)
    UINT64 iopm_pa;
    UINT64 msrpm_va;                    // AMD MSR permission map (8KB contiguous)
    UINT64 msrpm_pa;
    UINT32 asid;                        // AMD ASID

    //
    // VMM stack (32KB aligned so host NMI handler locates stack top from RSP)
    //
    PVOID  vmm_stack_raw;               // raw pointer for hv_free_contiguous
    UINT64 vmm_stack;                   // 32KB-aligned base VA

    UINT64 msr_bitmap_va;               // Intel MSR bitmap (4KB contiguous)
    UINT64 msr_bitmap_pa;
    UINT64 io_bitmap_va_a;              // Intel I/O bitmap A (4KB contiguous)
    UINT64 io_bitmap_pa_a;
    UINT64 io_bitmap_va_b;              // Intel I/O bitmap B (4KB contiguous)
    UINT64 io_bitmap_pa_b;
    UINT64 xss_bitmap_va;               // Intel XSS-exiting bitmap (4KB contiguous)
    UINT64 xss_bitmap_pa;

    EPT_POINTER         ept_pointer;    // Intel EPT pointer (shared table)
    UINT64              npt_cr3;        // AMD NPT PML4 physical address (shared table)

    PGUEST_REGS regs;
    UINT32      proc_index;             // system-wide logical processor index (all groups)
    UINT32      core_id;                // same as proc_index
    UINT32      exit_reason;
    UINT64      exit_qual;
    UINT64      vmexit_rip;
    BOOLEAN     in_root;
    BOOLEAN     launched;
    BOOLEAN     advance_rip;

    VMX_VMXOFF_STATE vmxoff;
    BOOLEAN          svm_off;

    //
    // stealth: per-VCPU TSC compensation state
    //
    UINT64  tsc_cpuid_entry;
    BOOLEAN tsc_rdtsc_armed;

    //
    // pending external interrupt for deferred re-injection
    //
    UINT8   pending_ext_vector;
    BOOLEAN has_pending_ext_interrupt;
    BOOLEAN defer_ext_by_cr8;           // deferred because CR8 >= vector>>4 (avoid INT-window livelock)
    BOOLEAN cr8_load_exiting_forced;    // TRUE if CPU forces CR8-load exiting as must-be-1

    //
    // pending NMI for deferred delivery via NMI-window exiting
    //
    BOOLEAN has_pending_nmi;
    BOOLEAN mov_dr_exiting;
    UINT8   guest_cr8;

    //
    // per-core private host GDT + saved original GDT/IDT/TR for teardown
    //
    PVOID   host_gdt;                   // pre-allocated 4KB contiguous page
    UINT64  original_gdt_base;
    UINT16  original_gdt_limit;
    UINT16  original_tr_selector;
    UINT64  original_idt_base;
    UINT16  original_idt_limit;

    //
    // per-vCPU diagnostics counters
    //
    UINT64  exit_count;
    UINT64  cpuid_exits;
    UINT64  msr_exits;
    UINT64  cr_exits;
    UINT64  ept_npt_exits;

} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;

#define VMCALL_TEST             0x00000001
#define VMCALL_VMXOFF           0x00000002

//
// diagnostic snapshot written by private host IDT fault handlers before halting
//
typedef struct _HOST_FAULT_INFO {
    volatile LONG valid;
    UINT32        vector;
    UINT64        error_code;
    UINT64        rip;
    UINT64        cs;
    UINT64        rflags;
    UINT64        rsp;
    UINT64        cr2;
} HOST_FAULT_INFO, *PHOST_FAULT_INFO;

typedef struct _HOST_IDT_STATE {
    DECLSPEC_ALIGN(16) IDT_GATE_DESCRIPTOR_64 idt[IDT_NUM_ENTRIES];
    BOOLEAN initialized;
} HOST_IDT_STATE, *PHOST_IDT_STATE;

extern VIRTUAL_MACHINE_STATE * g_vcpu;
extern EPT_STATE *             g_ept;
extern UINT32                  g_cpu_count;
extern UINT32                  g_vcpu_capacity;
extern HOST_IDT_STATE          g_host_idt;
extern HOST_FAULT_INFO         g_host_fault_info;
extern PVOID                   g_driver_base;
extern ULONG                   g_driver_size;
