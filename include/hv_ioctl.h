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
typedef uint8_t  UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
#endif

#define OPHION_DEVICE_NAME          L"\\Device\\Ophion"
#define OPHION_SYMLINK_NAME         L"\\DosDevices\\Ophion"
#define OPHION_USER_PATH            L"\\\\.\\Ophion"

#define IOCTL_BASE                  0x800
#define IOCTL_HV_STATUS             CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 0, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_HV_INFO               CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 1, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_HV_STATS              CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 2, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_HV_DRAIN_LOGS         CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 3, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_HV_FAULT_INFO         CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 4, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_HV_ADD_WATCHPOINT     CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 5, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_HV_REMOVE_WATCHPOINT  CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 6, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_HV_TRACE_MSR          CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 7, METHOD_BUFFERED, FILE_WRITE_ACCESS)

typedef struct _HV_INFO {
    UINT32 cpu_count;           // logical processors virtualized (all groups)
    UINT32 backend;             // HV_VENDOR of the active backend (1=Intel, 2=AMD)
    UINT32 maxphyaddr;
    UINT32 features;            // HV_FEAT_* bitmask
    CHAR   backend_name[16];
} HV_INFO, *PHV_INFO;

#define HV_FEAT_VPID_OR_ASID        (1U << 0)
#define HV_FEAT_EPT_OR_NPT          (1U << 1)
#define HV_FEAT_PRIVATE_HOST_CR3    (1U << 2)
#define HV_FEAT_PRIVATE_HOST_IDT    (1U << 3)
#define HV_FEAT_PRIVATE_HOST_GDT    (1U << 4)
#define HV_FEAT_1GB_PAGES           (1U << 5)
#define HV_FEAT_POWER_CALLBACK      (1U << 6)

typedef struct _HV_STATS {
    UINT32 cpu_count;
    UINT32 active_watchpoints;
    UINT64 total_exits;
    UINT64 cpuid_exits;
    UINT64 msr_exits;
    UINT64 cr_exits;
    UINT64 ept_npt_exits;
    UINT64 dyn_mmio_mapped;
    UINT64 watchpoint_hits;
    UINT64 min_exit_cycles;
    UINT64 max_exit_cycles;
    UINT64 total_exit_cycles;
} HV_STATS, *PHV_STATS;

//
// lock-free root-mode log entry (returned by IOCTL_HV_DRAIN_LOGS)
//
#define HV_LOG_EVT_NONE             0
#define HV_LOG_EVT_WATCHPOINT_HIT   1
#define HV_LOG_EVT_DYN_MMIO         2
#define HV_LOG_EVT_MSR_READ_TRACE   3
#define HV_LOG_EVT_MSR_WRITE_TRACE  4
#define HV_LOG_EVT_UNHANDLED_EXIT   5
#define HV_LOG_EVT_VMRESUME_FAIL    6

typedef struct _HV_LOG_ENTRY {
    UINT64 tsc;
    UINT32 cpu;
    UINT32 event_type;
    UINT64 arg1;
    UINT64 arg2;
} HV_LOG_ENTRY, *PHV_LOG_ENTRY;

typedef struct _HV_FAULT_REPORT {
    UINT32 valid;
    UINT32 vector;
    UINT64 error_code;
    UINT64 rip;
    UINT64 cs;
    UINT64 rflags;
    UINT64 rsp;
    UINT64 cr2;
} HV_FAULT_REPORT, *PHV_FAULT_REPORT;

//
// EPT/NPT 4KB physical-page watchpoint request
//
#define HV_WP_TRAP_READ             (1U << 0)
#define HV_WP_TRAP_WRITE            (1U << 1)
#define HV_WP_TRAP_EXEC             (1U << 2)

typedef struct _HV_WATCHPOINT_REQ {
    UINT64 phys_addr;           // 4KB page-aligned guest physical address
    UINT32 flags;               // HV_WP_TRAP_* bitmask
    UINT32 _reserved;
} HV_WATCHPOINT_REQ, *PHV_WATCHPOINT_REQ;

//
// dynamic MSR tracing request
//
typedef struct _HV_MSR_TRACE_REQ {
    UINT32 msr;
    UINT8  trace_read;          // 1 = intercept+log RDMSR, 0 = stop
    UINT8  trace_write;         // 1 = intercept+log WRMSR, 0 = stop
    UINT16 _reserved;
} HV_MSR_TRACE_REQ, *PHV_MSR_TRACE_REQ;
