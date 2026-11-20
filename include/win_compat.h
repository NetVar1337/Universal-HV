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
*   - processor-group APIs (KeQueryActiveProcessorCountEx,
*     KeGetProcessorNumberFromIndex, KeSetSystemGroupAffinityThread, ...)
*     exist since Windows 7 and support multi-group machines (>64 LPs).
*   - no hardcoded structure offsets are used anywhere in this project.
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
// contiguous physically-aligned allocation (VMXON/VMCS/VMCB/EPT/NPT/bitmaps)
//
PVOID hv_alloc_contiguous(SIZE_T size);
VOID  hv_free_contiguous(PVOID p);

//
// allocate contiguous memory with explicit power-of-2 VA+PA alignment
// (e.g., 32KB alignment for per-vCPU VMM stacks so NMI handlers can locate
// the stack top directly from RSP). returns aligned pointer and stores the
// raw pointer in *raw_out for hv_free_contiguous().
//
PVOID hv_alloc_aligned_contiguous(SIZE_T size, SIZE_T alignment, PVOID *raw_out);

//
// processor enumeration across ALL processor groups (multi-group machines
// with >64 logical processors are fully supported)
//
ULONG  hv_total_processor_count(VOID);       // KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS)
ULONG  hv_max_processor_count(VOID);         // KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS)
ULONG  hv_current_processor_index(VOID);     // system-wide index 0..N-1
USHORT hv_active_group_count(VOID);

//
// execute a callback at DISPATCH_LEVEL on every active logical processor
// across all processor groups using documented group-affinity APIs
// (KeGetProcessorNumberFromIndex + KeSetSystemGroupAffinityThread).
// must be called at PASSIVE_LEVEL.
//
typedef VOID (*PHV_PER_CPU_CALLBACK)(ULONG cpu_index, PVOID context);

VOID hv_for_each_cpu(PHV_PER_CPU_CALLBACK callback, PVOID context);
