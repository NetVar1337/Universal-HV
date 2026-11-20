/*
*   broadcast.c - multi-processor all-groups execution for hv init/teardown
*
*   uses documented Windows 7+ group-affinity APIs (KeGetProcessorNumberFromIndex
*   + KeSetSystemGroupAffinityThread) via hv_for_each_cpu() so every logical
*   processor across all processor groups (>64 LPs) is visited exactly once at
*   DISPATCH_LEVEL with zero cross-core init races.
*/
#include "hv.h"

static VOID
cpu_init_callback(ULONG cpu_index, PVOID context)
{
    UNREFERENCED_PARAMETER(cpu_index);
    UNREFERENCED_PARAMETER(context);

    if (g_hv_backend == &g_vmx_backend)
        asm_vmx_save_state();
    else if (g_hv_backend == &g_svm_backend)
        asm_svm_save_state();
}

static VOID
cpu_terminate_callback(ULONG cpu_index, PVOID context)
{
    UNREFERENCED_PARAMETER(context);

    //
    // only issue VMCALL/VMMCALL on processors that were actually virtualized —
    // executing it on a non-virtualized CPU raises #UD.
    //
    if (g_vcpu && cpu_index < g_vcpu_capacity && g_vcpu[cpu_index].launched)
    {
        if (g_hv_backend == &g_vmx_backend)
            asm_vmx_vmcall(VMCALL_VMXOFF, 0, 0, 0);
        else if (g_hv_backend == &g_svm_backend)
            asm_svm_vmcall(VMCALL_VMXOFF, 0, 0, 0);

        g_vcpu[cpu_index].launched = FALSE;
    }
}

VOID
broadcast_virtualize_all(VOID)
{
    hv_for_each_cpu(cpu_init_callback, NULL);
}

VOID
broadcast_terminate_all(VOID)
{
    hv_for_each_cpu(cpu_terminate_callback, NULL);
}
