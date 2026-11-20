/*
*   win_compat.c - windows version compatibility layer implementation
*/
#include "hv.h"

static PFN_ExAllocatePool2 g_pfn_ExAllocatePool2 = NULL;
static BOOLEAN             g_win_compat_ready   = FALSE;

BOOLEAN
win_compat_init(VOID)
{
    UNICODE_STRING name;

    //
    // resolve ExAllocatePool2 dynamically: it does not exist on Windows
    // versions older than 10 2004. on failure we fall back to
    // ExAllocatePoolWithTag(NonPagedPool), which exists everywhere.
    //
    RtlInitUnicodeString(&name, L"ExAllocatePool2");
    g_pfn_ExAllocatePool2 = (PFN_ExAllocatePool2)MmGetSystemRoutineAddress(&name);

    g_win_compat_ready = TRUE;

    DbgPrintEx(0, 0, "[hv] win_compat: ExAllocatePool2 %s\n",
             g_pfn_ExAllocatePool2 ? "available (2004+)" : "NOT found, using ExAllocatePoolWithTag fallback");
    return TRUE;
}

PVOID
hv_pool_alloc(SIZE_T size)
{
    if (g_pfn_ExAllocatePool2)
        return g_pfn_ExAllocatePool2(POOL_FLAG_NON_PAGED, size, HV_POOL_TAG);

    //
    // Windows 7 / 8 / 8.1 / early Win10: NonPagedPool is NX on Win8+,
    // and we never execute pool memory anyway.
    //
    return ExAllocatePoolWithTag(NonPagedPool, size, HV_POOL_TAG);
}

VOID
hv_pool_free(PVOID p)
{
    if (!p)
        return;
    ExFreePoolWithTag(p, HV_POOL_TAG);
}

PVOID
hv_alloc_contiguous(SIZE_T size)
{
    PHYSICAL_ADDRESS max_phys;
    max_phys.QuadPart = MAXULONG64;
    return MmAllocateContiguousMemory(size, max_phys);
}

VOID
hv_free_contiguous(PVOID p)
{
    if (p)
        MmFreeContiguousMemory(p);
}

ULONG
hv_total_processor_count(VOID)
{
    //
    // ALL_PROCESSOR_GROUPS (0xFFFF) — total logical processors across all
    // groups. on single-group machines this equals KeQueryActiveProcessorCount(0).
    //
    return KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
}

ULONG
hv_current_processor_index(VOID)
{
    //
    // KeGetCurrentProcessorNumberEx returns the SYSTEM-WIDE processor index
    // (dense 0..N-1 across all groups), which is what we use to index g_vcpu.
    //
    return KeGetCurrentProcessorNumberEx(NULL);
}

USHORT
hv_active_group_count(VOID)
{
    USHORT groups = KeQueryActiveGroupCount();
    return groups ? groups : 1;
}

VOID
hv_generic_call_dpc_all_groups(PHV_DPC_ROUTINE Routine, PVOID Context)
{
    USHORT groups = hv_active_group_count();

    if (groups <= 1)
    {
        KeGenericCallDpc((PKDEFERRED_ROUTINE)Routine, Context);
        return;
    }

    //
    // KeGenericCallDpc only signals the processors of the caller's current
    // group. to reach every logical processor on multi-group machines
    // (>64 logical processors), switch the current thread into each group
    // and issue the broadcast there.
    //
    for (USHORT g = 0; g < groups; g++)
    {
        GROUP_AFFINITY ga;
        RtlZeroMemory(&ga, sizeof(ga));
        ga.Group = g;
        ga.Mask  = (KAFFINITY)-1;   // masked down to the group by the kernel
        KeSetSystemAffinityThreadEx(&ga);
        KeGenericCallDpc((PKDEFERRED_ROUTINE)Routine, Context);
    }

    KeRevertToUserAffinityThread();
}
