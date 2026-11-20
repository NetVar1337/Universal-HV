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

    HV_LOG("win_compat: ExAllocatePool2 %s\n",
           g_pfn_ExAllocatePool2 ? "available (2004+)" : "NOT found, using ExAllocatePoolWithTag fallback");
    return TRUE;
}

PVOID
hv_pool_alloc(SIZE_T size)
{
    if (g_pfn_ExAllocatePool2)
        return g_pfn_ExAllocatePool2(POOL_FLAG_NON_PAGED, size, HV_POOL_TAG);

#pragma warning(push)
#pragma warning(disable : 4996)
    return ExAllocatePoolWithTag(NonPagedPool, size, HV_POOL_TAG);
#pragma warning(pop)
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
    max_phys.QuadPart = (LONGLONG)MAXULONG64;
    return MmAllocateContiguousMemory(size, max_phys);
}

VOID
hv_free_contiguous(PVOID p)
{
    if (p)
        MmFreeContiguousMemory(p);
}

PVOID
hv_alloc_aligned_contiguous(SIZE_T size, SIZE_T alignment, PVOID *raw_out)
{
    if (!raw_out || alignment == 0 || (alignment & (alignment - 1)) != 0)
        return NULL;

    *raw_out = NULL;

    //
    // over-allocate by alignment bytes so we can round the VA up to an exact
    // power-of-2 boundary (MmAllocateContiguousMemory already aligns to 4KB,
    // and larger alignments like 32KB for VMM stacks are guaranteed here).
    //
    SIZE_T alloc_size = size + alignment;
    PVOID raw = hv_alloc_contiguous(alloc_size);
    if (!raw)
        return NULL;

    ULONG_PTR aligned = ((ULONG_PTR)raw + (alignment - 1)) & ~(alignment - 1);
    *raw_out = raw;
    return (PVOID)aligned;
}

ULONG
hv_total_processor_count(VOID)
{
    return KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
}

ULONG
hv_max_processor_count(VOID)
{
    ULONG max_cpus = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
    ULONG active   = hv_total_processor_count();
    return (max_cpus >= active) ? max_cpus : active;
}

ULONG
hv_current_processor_index(VOID)
{
    return KeGetCurrentProcessorNumberEx(NULL);
}

USHORT
hv_active_group_count(VOID)
{
    USHORT groups = KeQueryActiveGroupCount();
    return groups ? groups : 1;
}

VOID
hv_for_each_cpu(PHV_PER_CPU_CALLBACK callback, PVOID context)
{
    ULONG count = hv_total_processor_count();

    for (ULONG i = 0; i < count; i++)
    {
        PROCESSOR_NUMBER proc_num;
        GROUP_AFFINITY   affinity;
        GROUP_AFFINITY   prev_affinity;
        KIRQL            old_irql;

        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(i, &proc_num)))
            continue;

        RtlZeroMemory(&affinity, sizeof(affinity));
        RtlZeroMemory(&prev_affinity, sizeof(prev_affinity));
        affinity.Group = proc_num.Group;
        affinity.Mask  = (KAFFINITY)(1ULL << proc_num.Number);

        KeSetSystemGroupAffinityThread(&affinity, &prev_affinity);

        KeRaiseIrql(DISPATCH_LEVEL, &old_irql);
        callback(i, context);
        KeLowerIrql(old_irql);

        KeRevertToUserGroupAffinityThread(&prev_affinity);
    }
}
