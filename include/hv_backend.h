/*
*   hv_backend.h - hardware virtualization backend abstraction
*
*   the driver supports two interchangeable backends selected at load time
*   from the CPU vendor:
*
*     Intel  -> VMX backend  (src/vmx.c, src/vmexit.c, asm/AsmVmx*.asm)
*     AMD    -> SVM backend  (src/svm.c, asm/AsmSvm.asm)
*
*   shared infrastructure (EPT/NPT, stealth, private host GDT/IDT/CR3,
*   broadcast) is backend-agnostic and lives in its own modules.
*/
#pragma once

#include <ntddk.h>
#include "cpuinfo.h"
#include "hv_types.h"

typedef struct _HV_BACKEND {
    HV_VENDOR  vendor;
    const char *name;

    //
    // is this backend usable on the current CPU?
    //
    BOOLEAN (*check_support)(VOID);

    //
    // full init: allocate per-cpu state and virtualize every logical
    // processor in every group. called once at PASSIVE_LEVEL.
    //
    BOOLEAN (*init)(VOID);

    //
    // stop virtualizing all processors and free everything.
    //
    VOID (*terminate)(VOID);

    //
    // per-cpu entry, executed via DPC broadcast on each logical processor.
    // guest_stack = the DPC stack pointer to resume the guest at.
    //
    BOOLEAN (*virtualize_cpu)(PVOID guest_stack);

    //
    // per-cpu teardown (VMCALL/VMMCALL path), executed via DPC broadcast.
    //
    VOID (*terminate_cpu)(VOID);
} HV_BACKEND, *PHV_BACKEND;

extern const HV_BACKEND *g_hv_backend;

extern const HV_BACKEND g_vmx_backend;
extern const HV_BACKEND g_svm_backend;
