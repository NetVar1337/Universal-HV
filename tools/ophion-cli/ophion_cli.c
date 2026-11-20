/*
*   ophion_cli.c - usermode diagnostic & control CLI for the Ophion hypervisor
*
*   Build (from VS x64 Developer Command Prompt):
*     cl /W4 /WX /O2 /I..\..\include ophion_cli.c /Fe:ophion-cli.exe
*/
#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hv_ioctl.h"

static HANDLE
open_device(DWORD access)
{
    HANDLE h = CreateFileW(
        OPHION_USER_PATH,
        access,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (h == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        fprintf(stderr, "Failed to open %ls (Win32 error %lu).\n", OPHION_USER_PATH, err);
        if (err == ERROR_ACCESS_DENIED)
            fprintf(stderr, "Hint: Ophion requires Administrator (SeLoadDriverPrivilege).\n");
        else if (err == ERROR_FILE_NOT_FOUND)
            fprintf(stderr, "Hint: Ensure Ophion.sys is loaded and active.\n");
    }
    return h;
}

static const char *
log_event_name(UINT32 evt)
{
    switch (evt)
    {
    case HV_LOG_EVT_WATCHPOINT_HIT:  return "WATCHPOINT_HIT";
    case HV_LOG_EVT_DYN_MMIO:        return "DYN_MMIO_MAP";
    case HV_LOG_EVT_MSR_READ_TRACE:  return "MSR_READ";
    case HV_LOG_EVT_MSR_WRITE_TRACE: return "MSR_WRITE";
    case HV_LOG_EVT_UNHANDLED_EXIT:  return "UNHANDLED_EXIT";
    case HV_LOG_EVT_VMRESUME_FAIL:   return "VMRESUME_FAIL";
    default:                         return "UNKNOWN";
    }
}

static int
cmd_info(void)
{
    HANDLE h = open_device(GENERIC_READ);
    if (h == INVALID_HANDLE_VALUE)
        return 1;

    UINT32  active_cpus = 0;
    HV_INFO info        = {0};
    DWORD   bytes       = 0;

    if (DeviceIoControl(h, IOCTL_HV_STATUS, NULL, 0, &active_cpus, sizeof(active_cpus), &bytes, NULL))
        printf("Active CPUs     : %u\n", active_cpus);

    if (DeviceIoControl(h, IOCTL_HV_INFO, NULL, 0, &info, sizeof(info), &bytes, NULL))
    {
        printf("Backend         : %s (vendor=%u)\n", info.backend_name, info.backend);
        printf("Virtualized LPs : %u\n", info.cpu_count);
        printf("MAXPHYADDR      : %u bits\n", info.maxphyaddr);
        printf("Features        : 0x%08X [%s%s%s%s%s%s%s]\n",
               info.features,
               (info.features & HV_FEAT_VPID_OR_ASID)     ? "VPID/ASID " : "",
               (info.features & HV_FEAT_EPT_OR_NPT)       ? "EPT/NPT "   : "",
               (info.features & HV_FEAT_1GB_PAGES)        ? "1GB-PAGES " : "",
               (info.features & HV_FEAT_PRIVATE_HOST_CR3) ? "HOST-CR3 "  : "",
               (info.features & HV_FEAT_PRIVATE_HOST_IDT) ? "HOST-IDT "  : "",
               (info.features & HV_FEAT_PRIVATE_HOST_GDT) ? "HOST-GDT "  : "",
               (info.features & HV_FEAT_POWER_CALLBACK)   ? "S3/S4-CB"   : "");
    }
    else
    {
        fprintf(stderr, "IOCTL_HV_INFO failed (error %lu)\n", GetLastError());
        CloseHandle(h);
        return 1;
    }

    CloseHandle(h);
    return 0;
}

static int
cmd_stats(void)
{
    HANDLE h = open_device(GENERIC_READ);
    if (h == INVALID_HANDLE_VALUE)
        return 1;

    HV_STATS stats = {0};
    DWORD    bytes = 0;

    if (!DeviceIoControl(h, IOCTL_HV_STATS, NULL, 0, &stats, sizeof(stats), &bytes, NULL))
    {
        fprintf(stderr, "IOCTL_HV_STATS failed (error %lu)\n", GetLastError());
        CloseHandle(h);
        return 1;
    }

    UINT64 avg = stats.total_exits ? (stats.total_exit_cycles / stats.total_exits) : 0;

    printf("CPUs               : %u\n", stats.cpu_count);
    printf("Total exits        : %llu\n", (unsigned long long)stats.total_exits);
    printf("  CPUID            : %llu\n", (unsigned long long)stats.cpuid_exits);
    printf("  MSR              : %llu\n", (unsigned long long)stats.msr_exits);
    printf("  CR               : %llu\n", (unsigned long long)stats.cr_exits);
    printf("  EPT / NPT        : %llu\n", (unsigned long long)stats.ept_npt_exits);
    printf("Dynamic MMIO maps  : %llu\n", (unsigned long long)stats.dyn_mmio_mapped);
    printf("Watchpoints active : %u (hits: %llu)\n",
           stats.active_watchpoints, (unsigned long long)stats.watchpoint_hits);
    printf("Exit latency (TSC) : min=%llu avg=%llu max=%llu\n",
           (unsigned long long)stats.min_exit_cycles,
           (unsigned long long)avg,
           (unsigned long long)stats.max_exit_cycles);

    CloseHandle(h);
    return 0;
}

static int
cmd_logs(void)
{
    HANDLE h = open_device(GENERIC_READ);
    if (h == INVALID_HANDLE_VALUE)
        return 1;

    HV_LOG_ENTRY entries[128];
    DWORD        bytes = 0;

    if (!DeviceIoControl(h, IOCTL_HV_DRAIN_LOGS, NULL, 0, entries, sizeof(entries), &bytes, NULL))
    {
        fprintf(stderr, "IOCTL_HV_DRAIN_LOGS failed (error %lu)\n", GetLastError());
        CloseHandle(h);
        return 1;
    }

    UINT32 count = bytes / sizeof(HV_LOG_ENTRY);
    printf("Drained %u log entries:\n", count);
    for (UINT32 i = 0; i < count; i++)
    {
        printf("  [cpu=%2u tsc=%llu] %-15s arg1=0x%016llX arg2=0x%016llX\n",
               entries[i].cpu,
               (unsigned long long)entries[i].tsc,
               log_event_name(entries[i].event_type),
               (unsigned long long)entries[i].arg1,
               (unsigned long long)entries[i].arg2);
    }

    CloseHandle(h);
    return 0;
}

static int
cmd_fault(void)
{
    HANDLE h = open_device(GENERIC_READ);
    if (h == INVALID_HANDLE_VALUE)
        return 1;

    HV_FAULT_REPORT rep = {0};
    DWORD           bytes = 0;

    if (!DeviceIoControl(h, IOCTL_HV_FAULT_INFO, NULL, 0, &rep, sizeof(rep), &bytes, NULL))
    {
        fprintf(stderr, "IOCTL_HV_FAULT_INFO failed (error %lu)\n", GetLastError());
        CloseHandle(h);
        return 1;
    }

    if (!rep.valid)
    {
        printf("No host-mode faults recorded.\n");
    }
    else
    {
        printf("HOST FAULT RECORDED:\n");
        printf("  Vector : 0x%X\n", rep.vector);
        printf("  Error  : 0x%llX\n", (unsigned long long)rep.error_code);
        printf("  RIP    : 0x%016llX (CS=0x%llX)\n", (unsigned long long)rep.rip, (unsigned long long)rep.cs);
        printf("  RSP    : 0x%016llX\n", (unsigned long long)rep.rsp);
        printf("  RFLAGS : 0x%016llX\n", (unsigned long long)rep.rflags);
        printf("  CR2    : 0x%016llX\n", (unsigned long long)rep.cr2);
    }

    CloseHandle(h);
    return 0;
}

static int
cmd_watchpoint(int add, const char *addr_str, const char *flags_str)
{
    HANDLE h = open_device(GENERIC_READ | GENERIC_WRITE);
    if (h == INVALID_HANDLE_VALUE)
        return 1;

    HV_WATCHPOINT_REQ req = {0};
    req.phys_addr = _strtoui64(addr_str, NULL, 0);

    if (add)
    {
        if (flags_str)
        {
            if (strchr(flags_str, 'r') || strchr(flags_str, 'R')) req.flags |= HV_WP_TRAP_READ;
            if (strchr(flags_str, 'w') || strchr(flags_str, 'W')) req.flags |= HV_WP_TRAP_WRITE;
            if (strchr(flags_str, 'x') || strchr(flags_str, 'X')) req.flags |= HV_WP_TRAP_EXEC;
        }
        if (req.flags == 0)
            req.flags = HV_WP_TRAP_WRITE;
    }

    DWORD bytes = 0;
    DWORD ioctl = add ? IOCTL_HV_ADD_WATCHPOINT : IOCTL_HV_REMOVE_WATCHPOINT;
    if (!DeviceIoControl(h, ioctl, &req, sizeof(req), NULL, 0, &bytes, NULL))
    {
        fprintf(stderr, "Watchpoint IOCTL failed (error %lu)\n", GetLastError());
        CloseHandle(h);
        return 1;
    }

    printf("%s watchpoint at PA 0x%llX (flags=0x%X)\n",
           add ? "Installed" : "Removed",
           (unsigned long long)(req.phys_addr & ~0xFFFULL),
           req.flags);
    CloseHandle(h);
    return 0;
}

static int
cmd_trace_msr(const char *msr_str, const char *mode_str)
{
    HANDLE h = open_device(GENERIC_READ | GENERIC_WRITE);
    if (h == INVALID_HANDLE_VALUE)
        return 1;

    HV_MSR_TRACE_REQ req = {0};
    req.msr = (UINT32)strtoul(msr_str, NULL, 0);

    if (mode_str && strcmp(mode_str, "off") != 0)
    {
        if (strchr(mode_str, 'r') || strchr(mode_str, 'R')) req.trace_read  = 1;
        if (strchr(mode_str, 'w') || strchr(mode_str, 'W')) req.trace_write = 1;
    }

    DWORD bytes = 0;
    if (!DeviceIoControl(h, IOCTL_HV_TRACE_MSR, &req, sizeof(req), NULL, 0, &bytes, NULL))
    {
        fprintf(stderr, "IOCTL_HV_TRACE_MSR failed (error %lu)\n", GetLastError());
        CloseHandle(h);
        return 1;
    }

    printf("MSR 0x%X trace updated: read=%u write=%u\n", req.msr, req.trace_read, req.trace_write);
    CloseHandle(h);
    return 0;
}

static int
cmd_selftest(void)
{
    int regs1[4] = {0};
    int regs2[4] = {0};
    int failures = 0;

    // 1. CPUID.1:ECX[31] hypervisor present bit
    __cpuidex(regs1, 1, 0);
    printf("[selftest] CPUID.1:ECX[31] (HV present) = %u\n", ((UINT32)regs1[2] >> 31) & 1U);

    // 2. CPUID invalid leaf consistency (0x40000000 vs 0x13371337)
    __cpuidex(regs1, 0x40000000, 0);
    __cpuidex(regs2, 0x13371337, 0);
    if (memcmp(regs1, regs2, sizeof(regs1)) == 0)
    {
        printf("[selftest] PASS: CPUID(0x40000000) == CPUID(0x13371337)\n");
    }
    else
    {
        printf("[selftest] INFO: CPUID(0x40000000) != CPUID(0x13371337) (expected if stealth off or under another HV)\n");
    }

    // 3. Extended max leaf sanity (must have bit 31 set, e.g. 0x80000008+)
    __cpuidex(regs1, (int)0x80000000, 0);
    if (((UINT32)regs1[0]) < 0x80000000U)
    {
        printf("[selftest] FAIL: CPUID(0x80000000).EAX = 0x%08X\n", (UINT32)regs1[0]);
        failures++;
    }
    else
    {
        printf("[selftest] PASS: CPUID(0x80000000).EAX = 0x%08X\n", (UINT32)regs1[0]);
    }

    return failures ? 1 : 0;
}

static void
usage(void)
{
    printf("Ophion Hypervisor CLI\n\n"
           "Usage:\n"
           "  ophion-cli info                       Show backend, CPU count, and features\n"
           "  ophion-cli stats                      Show VM-exit counters & cycle latency\n"
           "  ophion-cli logs                       Drain lock-free root-mode event ring\n"
           "  ophion-cli fault                      Show recorded host-mode fault info\n"
           "  ophion-cli wp-add <phys_hex> [r|w|x]  Add 4KB EPT/NPT watchpoint\n"
           "  ophion-cli wp-del <phys_hex>          Remove 4KB EPT/NPT watchpoint\n"
           "  ophion-cli msr <msr_hex> <r|w|rw|off> Toggle dynamic MSR read/write tracing\n"
           "  ophion-cli selftest                   Run local usermode CPUID sanity checks\n");
}

int
main(int argc, char **argv)
{
    if (argc < 2)
    {
        usage();
        return 0;
    }

    if (strcmp(argv[1], "info") == 0)
        return cmd_info();
    if (strcmp(argv[1], "stats") == 0)
        return cmd_stats();
    if (strcmp(argv[1], "logs") == 0)
        return cmd_logs();
    if (strcmp(argv[1], "fault") == 0)
        return cmd_fault();
    if (strcmp(argv[1], "wp-add") == 0 && argc >= 3)
        return cmd_watchpoint(1, argv[2], argc >= 4 ? argv[3] : "w");
    if (strcmp(argv[1], "wp-del") == 0 && argc >= 3)
        return cmd_watchpoint(0, argv[2], NULL);
    if (strcmp(argv[1], "msr") == 0 && argc >= 4)
        return cmd_trace_msr(argv[2], argv[3]);
    if (strcmp(argv[1], "selftest") == 0)
        return cmd_selftest();

    usage();
    return 1;
}
