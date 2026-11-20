/*
*   cpuinfo.h - cpu vendor detection and virtualization capability probing
*
*   detects GenuineIntel vs AuthenticAMD, physical address width, and the
*   available hardware virtualization extension (Intel VT-x/VMX vs AMD-V/SVM).
*   all hypervisor decisions branch off g_cpu so the rest of the code is
*   vendor-neutral.
*/
#pragma once

#include <ntddk.h>
#include <intrin.h>
#include "ia32.h"

typedef enum _HV_VENDOR {
    HV_VENDOR_UNKNOWN = 0,
    HV_VENDOR_INTEL,
    HV_VENDOR_AMD
} HV_VENDOR;

//
// CPUID leaves
//
#define CPUID_MAX_STD_LEAF          0x00000000
#define CPUID_VERSION_FEATURES      0x00000001
#define CPUID_EXT_MAX_LEAF          0x80000000
#define CPUID_EXT_FEATURES          0x80000001
#define CPUID_ADDR_BITS             0x80000008
#define CPUID_SVM_INFO              0x8000000A

#define CPUID_VMX_BIT               5       // CPUID.1:ECX[5]  — VMX
#define CPUID_SVM_BIT               2       // CPUID.80000001:ECX[2] — SVM
#define CPUID_HYPERVISOR_BIT        31      // CPUID.1:ECX[31] — hypervisor present

//
// AMD SVM MSRs / bits
//
#define MSR_EFER                    0xC0000080
#define EFER_SVME                   (1ULL << 12)
#define MSR_VM_CR                   0xC0010114
#define MSR_VM_HSAVE_PA             0xC0010117
#define VM_CR_SVM_DIS               (1ULL << 0)     // BIOS-locked SVM disable

//
// CPUID.8000000A EDX feature bits
//
#define SVM_FEATURE_NP              (1U << 0)       // nested paging
#define SVM_FEATURE_NRIPS           (1U << 3)       // NRIP save (next_rip valid)
#define SVM_FEATURE_VMCB_CLEAN      (1U << 5)
#define SVM_FEATURE_FLUSH_BY_ASID   (1U << 6)
#define SVM_FEATURE_DECODE_ASSISTS  (1U << 7)

typedef struct _CPU_CAPS {
    HV_VENDOR vendor;
    CHAR      vendor_string[13];        // 12 chars + NUL

    UINT32    max_std_leaf;
    UINT32    max_ext_leaf;
    UINT8     maxphyaddr;               // physical address width in bits

    BOOLEAN   hypervisor_present;       // already running under a hypervisor (e.g. Hyper-V)

    //
    // Intel VT-x
    //
    BOOLEAN   vmx_capable;              // CPUID.1:ECX[5]
    BOOLEAN   vmx_usable;               // IA32_FEATURE_CONTROL allows VMX outside SMX
    IA32_FEATURE_CONTROL_REGISTER feature_control;

    //
    // AMD SVM
    //
    BOOLEAN   svm_capable;              // CPUID.80000001:ECX[2]
    BOOLEAN   svm_usable;               // not BIOS-locked via VM_CR
    UINT32    svm_features;             // CPUID.8000000A:EDX
    UINT32    svm_num_asids;            // CPUID.8000000A:EBX
    UINT64    vm_cr;
} CPU_CAPS, *PCPU_CAPS;

extern CPU_CAPS g_cpu;

BOOLEAN cpuinfo_init(VOID);

//
// intel: make sure VMX can be enabled outside SMX. if IA32_FEATURE_CONTROL
// is unlocked we set EnableVmxOutsideSmx + Lock ourselves (some firmware
// leaves it unlocked). returns FALSE if VMX is locked off (e.g. Hyper-V
// owns it or BIOS disabled VT-x) — the caller then fails gracefully.
//
BOOLEAN cpuinfo_vmx_enable(VOID);

//
// amd: returns TRUE if SVM is present and not locked by firmware
//
BOOLEAN cpuinfo_svm_check(VOID);
