/*
*   hv_types.h - core hypervisor type definitions — per-vcpu state, ept structures, configs
*   zero windows api dependency in vmx/svm-root mode by design
*/
#pragma once

#include "ia32.h"

#ifndef MAXULONG64
#define MAXULONG64              ((ULONG64)~((ULONG64)0))
#endif

#define VMM_STACK_SIZE          0x8000      // 32 KB per-VCPU VMM stack
#define VMM_STACK_VCPU_OFFSET   8           // vcpu ptr stored at top-8 of stack
#define VMXON_SIZE              0x1000
#define VMCS_SIZE               0x1000
#define VMCB_SIZE               0x1000      // SVM VMCB is one 4KB page
#define IOPM_SIZE               0x3000      // SVM I/O permission map (3 pages)
#define MAX_MTRR_RANGES         256
#define MAX_RAM_RANGES          256

#define HV_POOL_TAG             'nhpO'

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
    UINT64  guest_cr3;
} VMX_VMXOFF_STATE;

typedef struct _MTRR_RANGE_DESCRIPTOR {
    UINT64  phys_base;
    UINT64  phys_end;
    UINT8   mem_type;
    BOOLEAN fixed;
} MTRR_RANGE_DESCRIPTOR;

typedef struct _RAM_RANGE {
    UINT64 base;
    UINT64 end;     // inclusive
} RAM_RANGE;

//
// dynamic EPT/NPT page table.
//
// the identity map is built on demand:
//   PML4[512]      — always fully present in the struct
//   PML3[i]        — allocated (4KB, physically page-aligned) only for
//                    512GB regions that contain RAM or are below 4GB (MMIO)
//   PML2 tables    — allocated per 1GB chunk that needs mapping
//   PML1 tables    — allocated per 2MB chunk that crosses an MTRR boundary
//
// all allocated table pages are tracked on AllocList for teardown.
// one table set is shared by all vCPUs (the identity map is identical);
// per-vCPU EPT pointers all reference it.
//
typedef struct _VMM_EPT_ALLOC {
    LIST_ENTRY Link;
    PVOID      Page;
} VMM_EPT_ALLOC, *PVMM_EPT_ALLOC;

typedef struct _VMM_EPT_PAGE_TABLE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4_ENTRY PML4[512];
    PVOID      PML3[512];               // VA of each allocated PML3 table (NULL = absent)
    LIST_ENTRY AllocList;               // all table pages (PML3/PML2/PML1)
    UINT32     AllocCount;
} VMM_EPT_PAGE_TABLE, *PVMM_EPT_PAGE_TABLE;

typedef struct _EPT_STATE {
    MTRR_RANGE_DESCRIPTOR mem_ranges[MAX_MTRR_RANGES];
    UINT32                num_ranges;
    UINT8                 default_type;
    BOOLEAN               ad_supported;
    LIST_ENTRY            hooked_pages;    // reserved for future EPT hooks

    //
    // physical memory map (from MmGetPhysicalMemoryRanges) — used to size
    // the identity map correctly on machines with >512GB RAM / LA57
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

    //
    // TRUE if VPID was actually enabled in the VMCS (Intel). when FALSE,
    // INVVPID must never be executed (it would #UD in VMX root).
    //
    BOOLEAN               vpid_enabled;

    //
    // TRUE if AMD nested paging is available (CPUID.8000000A:EDX bit 0)
    //
    BOOLEAN               npt_supported;
} EPT_STATE, *PEPT_STATE;

typedef struct _VIRTUAL_MACHINE_STATE {

    UINT64 vmxon_va;                    // Intel VMXON region
    UINT64 vmxon_pa;
    UINT64 vmcs_va;                     // Intel VMCS region
    UINT64 vmcs_pa;

    UINT64 vmcb_va;                     // AMD VMCB (one page)
    UINT64 vmcb_pa;
    UINT64 hsave_va;                    // AMD host save area (one page)
    UINT64 hsave_pa;
    UINT64 iopm_va;                     // AMD IOPM (3 pages)
    UINT64 iopm_pa;
    UINT64 msrpm_va;                    // AMD MSR permission map (8KB)
    UINT64 msrpm_pa;
    UINT32 asid;                        // AMD ASID

    //
    // VMM stack (HOST_RSP points near top of this)
    //
    UINT64 vmm_stack;

    UINT64 msr_bitmap_va;               // Intel MSR bitmap
    UINT64 msr_bitmap_pa;
    UINT64 io_bitmap_va_a;              // Intel I/O bitmaps
    UINT64 io_bitmap_pa_a;
    UINT64 io_bitmap_va_b;
    UINT64 io_bitmap_pa_b;

    EPT_POINTER         ept_pointer;    // Intel EPT pointer (shared table)
    UINT64              npt_cr3;        // AMD NPT PML4 physical address (shared table)

    PGUEST_REGS regs;
    UINT32      proc_index;             // system-wide logical processor index (all groups)
    UINT32      core_id;                // same as proc_index (kept for readability)
    UINT32      exit_reason;
    UINT64      exit_qual;
    UINT64      vmexit_rip;
    BOOLEAN     in_root;
    BOOLEAN     launched;
    BOOLEAN     advance_rip;

    VMX_VMXOFF_STATE vmxoff;

    //
    // SVM: set when the guest issued the shutdown VMMCALL — all intercepts
    // are cleared and the vCPU resumes without further exits.
    //
    BOOLEAN     svm_off;

    //
    // stealth: per-VCPU TSC compensation state for "trap next RDTSC" approach.
    //
    UINT64  tsc_cpuid_entry;
    BOOLEAN tsc_rdtsc_armed;

    //
    // pending external interrupt for deferred re-injection
    //
    UINT8   pending_ext_vector;
    BOOLEAN has_pending_ext_interrupt;

    //
    // pending NMI for deferred delivery via NMI-window exiting
    //
    BOOLEAN has_pending_nmi;

    // guest DR0-DR3/DR6 saved on vm-exit, restored before vmresume
    UINT64  guest_dr0;
    UINT64  guest_dr1;
    UINT64  guest_dr2;
    UINT64  guest_dr3;
    UINT64  guest_dr6;
    BOOLEAN mov_dr_exiting;

    // shadowed guest CR8 (TPR) for interrupt priority checks
    UINT8   guest_cr8;

    // per-core private host GDT for VMXOFF restore
    PVOID   host_gdt;
    UINT64  original_gdt_base;
    UINT16  original_gdt_limit;
    UINT16  original_tr_selector;

} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;

#define VMCALL_TEST             0x00000001
#define VMCALL_VMXOFF           0x00000002

//
// single global NMI-pending flag for the private host IDT NMI handler.
// there is exactly one guest OS on the machine, so a per-cpu index is not
// required; any VM-exit that observes the flag delivers the NMI into the
// guest. (also avoids relying on IA32_TSC_AUX, which is group-relative and
// ambiguous on multi-group machines.)
//
extern volatile LONG g_host_nmi_pending;

typedef struct _HOST_IDT_STATE {
    DECLSPEC_ALIGN(16) IDT_GATE_DESCRIPTOR_64 idt[IDT_NUM_ENTRIES];
    UINT64  original_idt_base;
    BOOLEAN initialized;
} HOST_IDT_STATE, *PHOST_IDT_STATE;

extern VIRTUAL_MACHINE_STATE * g_vcpu;
extern EPT_STATE *             g_ept;
extern UINT32                  g_cpu_count;
extern UINT64                  g_system_cr3;
extern UINT64 *                g_msr_bitmap_invalid;
extern HOST_IDT_STATE          g_host_idt;
