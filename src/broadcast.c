/*
*   broadcast.c - dpc-based broadcast for multi-processor hv operations
*
*   KeGenericCallDpc only reaches the processors of the caller's group, so
*   hv_generic_call_dpc_all_groups() (win_compat.c) switches the thread
*   through every processor group. this makes the hypervisor work on
*   machines with more than 64 logical processors (multi-group systems).
*/
#include "hv.h"

static VOID
dpc_init_guest(
    _In_ PKDPC  Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    //
    // saves gprs + rflags, calls the backend's virtualize_cpu(rsp).
    // on a successful launch/resume the CPU returns via the backend's
    // restore-state trampoline.
    //
    if (g_hv_backend == &g_vmx_backend)
        asm_vmx_save_state();
    else
        asm_svm_save_state();

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

static VOID
dpc_terminate_guest(
    _In_ PKDPC  Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    //
    // only issue the terminate call on processors that were actually
    // virtualized — VMCALL/VMMCALL on a non-virtualized cpu #UDs.
    //
    {
        ULONG idx = hv_current_processor_index();
        if (g_vcpu && idx < g_cpu_count && g_vcpu[idx].launched)
        {
            if (g_hv_backend == &g_vmx_backend)
                asm_vmx_vmcall(VMCALL_VMXOFF, 0, 0, 0);
            else
                asm_svm_vmcall(VMCALL_VMXOFF, 0, 0, 0);
        }
    }

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

VOID
broadcast_virtualize_all(VOID)
{
    hv_generic_call_dpc_all_groups(dpc_init_guest, NULL);
}

VOID
broadcast_terminate_all(VOID)
{
    hv_generic_call_dpc_all_groups(dpc_terminate_guest, NULL);
}
