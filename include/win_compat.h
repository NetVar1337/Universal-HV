/*
*   win_compat.h - windows version compatibility layer
*
*   goal: the driver must load and run on every x64 Windows from Windows 7
*   through Windows 11 24H2 / Server 2025, regardless of which WDK/SDK it
*   was built with.
*
*   - ExAllocatePool2 only exists on Windows 10 2004+; it is resolved
*     dynamically and falls back to ExAllocatePoolWithTag(NonPagedPool)
*     on older systems.
*   - processor-group APIs (KeQueryActiveProcessorCountEx, ...) exist since
*     Windows 7; they are linked directly and additionally used to support
*     machines with more than 64 logical processors (multiple groups).
*   - no hardcoded structure offsets are used anywhere in this project, so
*     build-to-build kernel layout changes do not matter.
*/
#pragma once

#include <ntddk.h>

//
// undocumented but long-stable export (present since Windows XP x64).
// returns a nonpaged-pool block of PHYSICAL_MEMORY_RANGE describing all
// RAM in the machine; free with ExFreePool.
//
NTKERNELAPI
PPHYSICAL_MEMORY_RANGE
MmGetPhysicalMemoryRanges(VOID);

//
// KeGenericCallDpc family — not declared in all WDK header versions we
// target (stable since Windows Vista); declared here once for all modules.
//
NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KeGenericCallDpc(
    _In_ PKDEFERRED_ROUTINE Routine,
    _In_opt_ PVOID          Context);

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KeSignalCallDpcDone(
    _In_ PVOID SystemArgument1);

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
LOGICAL
KeSignalCallDpcSynchronize(
    _In_ PVOID SystemArgument2);

//
// dynamically resolved ExAllocatePool2 (Windows 10 2004+, WDK 19041+)
//
typedef PVOID (NTAPI *PFN_ExAllocatePool2)(POOL_FLAGS Flags, SIZE_T NumberOfBytes, ULONG Tag);

BOOLEAN win_compat_init(VOID);

//
// pool helpers — non-paged, works on every supported Windows version
//
PVOID hv_pool_alloc(SIZE_T size);
VOID  hv_pool_free(PVOID p);

//
// contiguous physically-aligned allocation (VMXON/VMCS/VMCB/NPT tables)
//
PVOID hv_alloc_contiguous(SIZE_T size);
VOID  hv_free_contiguous(PVOID p);

//
// processor enumeration across ALL processor groups (multi-group machines
// with >64 logical processors are fully supported)
//
ULONG hv_total_processor_count(VOID);        // KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS)
ULONG hv_current_processor_index(VOID);      // system-wide index 0..N-1
USHORT hv_active_group_count(VOID);

//
// KeGenericCallDpc broadcasts only to the caller's group. this helper runs
// the DPC on every group by switching thread affinity group by group.
// must be called at PASSIVE_LEVEL.
//
typedef VOID (*PHV_DPC_ROUTINE)(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);

VOID hv_generic_call_dpc_all_groups(PHV_DPC_ROUTINE Routine, PVOID Context);
