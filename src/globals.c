/*
*   globals.c - global variable definitions
*/
#include "hv.h"

VIRTUAL_MACHINE_STATE *g_vcpu               = NULL;
EPT_STATE *g_ept                            = NULL;
UINT32 g_cpu_count                          = 0;
UINT32 g_vcpu_capacity                      = 0;
HOST_IDT_STATE g_host_idt                   = {0};
HOST_FAULT_INFO g_host_fault_info           = {0};
PVOID g_driver_base                         = NULL;
ULONG g_driver_size                         = 0;

const HV_BACKEND *g_hv_backend              = NULL;
BOOLEAN g_hv_active                         = FALSE;   // TRUE once all cpus are virtualized

BOOLEAN g_stealth_enabled                   = STEALTH_ENABLED;
STEALTH_CPUID_CACHE g_stealth_cpuid_cache   = {0};
