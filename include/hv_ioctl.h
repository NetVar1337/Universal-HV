/*
*   hv_ioctl.h - shared kernel/usermode IOCTL interface for Ophion
*/
#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#include <stdint.h>
typedef uint32_t UINT32;
typedef uint64_t UINT64;
#endif

#define OPHION_DEVICE_NAME      L"\\Device\\Ophion"
#define OPHION_SYMLINK_NAME     L"\\DosDevices\\Ophion"
#define OPHION_USER_PATH        L"\\\\.\\Ophion"

#define IOCTL_BASE              0x800
#define IOCTL_HV_STATUS         CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 0, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_HV_INFO           CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 1, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_HV_STATS          CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 2, METHOD_BUFFERED, FILE_READ_ACCESS)

typedef struct _HV_INFO {
    UINT32 cpu_count;           // logical processors virtualized (all groups)
    UINT32 backend;             // HV_VENDOR of the active backend (1=Intel, 2=AMD)
    UINT32 maxphyaddr;
    UINT32 features;            // bit0=vpid/asid, bit1=ept/npt, bit2=private_host_cr3, bit3=private_host_idt
    CHAR   backend_name[16];
} HV_INFO, *PHV_INFO;

#define HV_FEAT_VPID_OR_ASID        (1U << 0)
#define HV_FEAT_EPT_OR_NPT          (1U << 1)
#define HV_FEAT_PRIVATE_HOST_CR3    (1U << 2)
#define HV_FEAT_PRIVATE_HOST_IDT    (1U << 3)
#define HV_FEAT_PRIVATE_HOST_GDT    (1U << 4)

typedef struct _HV_STATS {
    UINT32 cpu_count;
    UINT32 _reserved;
    UINT64 total_exits;
    UINT64 cpuid_exits;
    UINT64 msr_exits;
    UINT64 cr_exits;
    UINT64 ept_npt_exits;
    UINT64 dyn_mmio_mapped;
} HV_STATS, *PHV_STATS;
