/*
*   driver.c - windows kernel driver entry point for Ophion
*
*   - selects Intel VMX or AMD SVM automatically from CPU vendor
*   - enforces admin/driver-load privilege on usermode handle opens
*   - creates the symbolic link only after virtualization succeeds
*   - handles S3/S4 power transitions (\Callback\PowerState) cleanly
*   - handles hot-added CPUs (KeRegisterProcessorChangeCallback)
*   - exposes status, info, exit profiler stats, lock-free root logs,
*     host fault reports, EPT/NPT watchpoints, and MSR tracing via IOCTLs
*/
#include "hv.h"

#ifndef SE_LOAD_DRIVER_PRIVILEGE
#define SE_LOAD_DRIVER_PRIVILEGE    (10L)
#endif

static PCALLBACK_OBJECT g_power_cb_obj      = NULL;
static PVOID            g_power_cb_reg      = NULL;
static PVOID            g_proc_change_reg   = NULL;

static NTSTATUS DriverCreateClose(PDEVICE_OBJECT device_obj, PIRP irp);
static NTSTATUS DriverIoControl(PDEVICE_OBJECT device_obj, PIRP irp);

//
// S3/S4 Power-State Callback (\Callback\PowerState):
//   Argument1 == PO_CB_SYSTEM_STATE_LOCK:
//     Argument2 == 0 -> system is about to leave S0 (sleep/hibernate):
//                       devirtualize all CPUs cleanly so resume doesn't see
//                       stale VMX/SVM state.
//     Argument2 == 1 -> system has returned to S0:
//                       re-virtualize all active logical processors.
//
static VOID
hv_power_state_callback(
    _In_opt_ PVOID callback_context,
    _In_opt_ PVOID argument1,
    _In_opt_ PVOID argument2)
{
    UNREFERENCED_PARAMETER(callback_context);

    if ((ULONG_PTR)argument1 != PO_CB_SYSTEM_STATE_LOCK)
        return;

    if ((ULONG_PTR)argument2 == 0)
    {
        HV_LOG("PowerState: leaving S0 (sleep/hibernate), devirtualizing...\n");
        if (g_hv_active)
        {
            broadcast_terminate_all();
            if (g_hv_backend)
                g_hv_backend->terminate();
            g_hv_active = FALSE;
        }
    }
    else
    {
        HV_LOG("PowerState: resumed to S0, re-virtualizing...\n");
        if (!g_hv_active && g_hv_backend)
        {
            if (g_hv_backend->init())
            {
                g_hv_active = TRUE;
                HV_LOG("PowerState: re-virtualized %u logical processors.\n", g_cpu_count);
            }
            else
            {
                HV_LOG("PowerState: re-virtualization failed; rolling back.\n");
                broadcast_terminate_all();
                g_hv_backend->terminate();
            }
        }
    }
}

//
// CPU Hot-Add Callback:
//   when a logical processor is dynamically added online, virtualize it using
//   its pre-allocated slot in g_vcpu (sized to hv_max_processor_count()).
//
static VOID
hv_processor_change_callback(
    _In_ PVOID callback_context,
    _In_ PKE_PROCESSOR_CHANGE_NOTIFY_CONTEXT change_context,
    _Inout_ PNTSTATUS operation_status)
{
    UNREFERENCED_PARAMETER(callback_context);
    UNREFERENCED_PARAMETER(operation_status);

    if (!g_hv_active || !g_hv_backend || !g_vcpu)
        return;

    if (change_context->State != KeProcessorAddCompleteNotify)
        return;

    ULONG idx = change_context->NtNumber;
    if (idx >= g_vcpu_capacity || g_vcpu[idx].launched)
        return;

    GROUP_AFFINITY affinity;
    GROUP_AFFINITY prev_affinity;
    KIRQL          old_irql;

    RtlZeroMemory(&affinity, sizeof(affinity));
    RtlZeroMemory(&prev_affinity, sizeof(prev_affinity));
    affinity.Group = change_context->ProcNumber.Group;
    affinity.Mask  = (KAFFINITY)(1ULL << change_context->ProcNumber.Number);

    KeSetSystemGroupAffinityThread(&affinity, &prev_affinity);
    KeRaiseIrql(DISPATCH_LEVEL, &old_irql);

    if (g_hv_backend == &g_vmx_backend)
        asm_vmx_save_state();
    else if (g_hv_backend == &g_svm_backend)
        asm_svm_save_state();

    KeLowerIrql(old_irql);
    KeRevertToUserGroupAffinityThread(&prev_affinity);

    if (g_vcpu[idx].launched)
    {
        g_cpu_count = hv_total_processor_count();
        HV_LOG("Hot-added CPU %u virtualized successfully.\n", idx);
    }
}

static VOID
hv_register_callbacks(VOID)
{
    UNICODE_STRING    cb_name;
    OBJECT_ATTRIBUTES obj_attr;

    RtlInitUnicodeString(&cb_name, L"\\Callback\\PowerState");
    InitializeObjectAttributes(&obj_attr, &cb_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    if (NT_SUCCESS(ExCreateCallback(&g_power_cb_obj, &obj_attr, FALSE, TRUE)))
    {
        g_power_cb_reg = ExRegisterCallback(g_power_cb_obj, hv_power_state_callback, NULL);
        if (!g_power_cb_reg)
        {
            ObDereferenceObject(g_power_cb_obj);
            g_power_cb_obj = NULL;
        }
    }

    g_proc_change_reg = KeRegisterProcessorChangeCallback(
        hv_processor_change_callback, NULL, 0);
}

static VOID
hv_unregister_callbacks(VOID)
{
    if (g_proc_change_reg)
    {
        KeDeregisterProcessorChangeCallback(g_proc_change_reg);
        g_proc_change_reg = NULL;
    }

    if (g_power_cb_reg)
    {
        ExUnregisterCallback(g_power_cb_reg);
        g_power_cb_reg = NULL;
    }

    if (g_power_cb_obj)
    {
        ObDereferenceObject(g_power_cb_obj);
        g_power_cb_obj = NULL;
    }
}

VOID
DriverUnload(_In_ PDRIVER_OBJECT driver_obj)
{
    UNICODE_STRING symlink;

    HV_LOG("Unloading hypervisor driver...\n");

    hv_unregister_callbacks();

    if (g_hv_active)
        broadcast_terminate_all();

    if (g_hv_backend)
        g_hv_backend->terminate();

    g_hv_active  = FALSE;
    g_hv_backend = NULL;

    RtlInitUnicodeString(&symlink, OPHION_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink);

    if (driver_obj->DeviceObject)
        IoDeleteDevice(driver_obj->DeviceObject);

    HV_LOG("Driver unloaded.\n");
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  driver_obj,
    _In_ PUNICODE_STRING registry_path)
{
    NTSTATUS       status;
    PDEVICE_OBJECT device_obj = NULL;
    UNICODE_STRING device_name;
    UNICODE_STRING symlink;

    UNREFERENCED_PARAMETER(registry_path);

    HV_LOG("Ophion initializing...\n");

    //
    // capture driver image span for minimal private host CR3 mapping
    //
    g_driver_base = driver_obj->DriverStart;
    g_driver_size = driver_obj->DriverSize;

    win_compat_init();
    cpuinfo_init();

    if (g_cpu.vendor == HV_VENDOR_INTEL && cpuinfo_vmx_enable())
        g_hv_backend = &g_vmx_backend;
    else if (g_cpu.vendor == HV_VENDOR_AMD && cpuinfo_svm_check())
        g_hv_backend = &g_svm_backend;

    if (!g_hv_backend)
    {
        HV_LOG("No usable hardware virtualization on this machine (vendor=%d vmx=%d svm=%d).\n",
               g_cpu.vendor, g_cpu.vmx_capable, g_cpu.svm_capable);
        return STATUS_NOT_SUPPORTED;
    }

    HV_LOG("Backend: %s\n", g_hv_backend->name);

    RtlInitUnicodeString(&device_name, OPHION_DEVICE_NAME);
    status = IoCreateDevice(
        driver_obj,
        0,
        &device_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &device_obj);

    if (!NT_SUCCESS(status))
    {
        HV_LOG("IoCreateDevice failed: 0x%X\n", status);
        g_hv_backend = NULL;
        return status;
    }

    driver_obj->DriverUnload                         = DriverUnload;
    driver_obj->MajorFunction[IRP_MJ_CREATE]         = DriverCreateClose;
    driver_obj->MajorFunction[IRP_MJ_CLOSE]          = DriverCreateClose;
    driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoControl;

    if (!g_hv_backend->check_support() || !g_hv_backend->init())
    {
        HV_LOG("Hypervisor initialization FAILED! Rolling back...\n");
        //
        // broadcast_terminate_all() safely guards on vcpu->launched so any
        // partially virtualized cores exit VMX/SVM cleanly BEFORE terminate()
        // frees VMCS/VMXON/VMCB/EPT/VMM stacks!
        //
        broadcast_terminate_all();
        g_hv_backend->terminate();
        IoDeleteDevice(device_obj);
        g_hv_backend = NULL;
        return STATUS_HV_OPERATION_FAILED;
    }

    g_hv_active = TRUE;

    //
    // register power-state (S3/S4) and CPU hot-add callbacks
    //
    hv_register_callbacks();

    //
    // expose symbolic link ONLY after virtualization is fully active
    //
    RtlInitUnicodeString(&symlink, OPHION_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlink, &device_name);
    if (!NT_SUCCESS(status))
    {
        HV_LOG("IoCreateSymbolicLink failed: 0x%X\n", status);
        hv_unregister_callbacks();
        broadcast_terminate_all();
        g_hv_backend->terminate();
        g_hv_active  = FALSE;
        g_hv_backend = NULL;
        IoDeleteDevice(device_obj);
        return status;
    }

    HV_LOG("Hypervisor (%s) loaded and active on all %u logical processors!\n",
           g_hv_backend->name, g_cpu_count);
    return STATUS_SUCCESS;
}

static NTSTATUS
DriverCreateClose(
    _In_ PDEVICE_OBJECT device_obj,
    _In_ PIRP           irp)
{
    NTSTATUS           status = STATUS_SUCCESS;
    PIO_STACK_LOCATION io_stack = IoGetCurrentIrpStackLocation(irp);

    UNREFERENCED_PARAMETER(device_obj);

    //
    // lock down \\.\Ophion: require SeLoadDriverPrivilege (Administrator / SYSTEM)
    // for any user-mode process opening a handle.
    //
    if (io_stack->MajorFunction == IRP_MJ_CREATE && irp->RequestorMode != KernelMode)
    {
        LUID load_priv = RtlConvertLongToLuid(SE_LOAD_DRIVER_PRIVILEGE);
        if (!SeSinglePrivilegeCheck(load_priv, irp->RequestorMode))
            status = STATUS_ACCESS_DENIED;
    }

    irp->IoStatus.Status      = status;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS
DriverIoControl(
    _In_ PDEVICE_OBJECT device_obj,
    _In_ PIRP           irp)
{
    NTSTATUS           status     = STATUS_SUCCESS;
    PIO_STACK_LOCATION io_stack   = IoGetCurrentIrpStackLocation(irp);
    ULONG              ioctl_code = io_stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG              in_len     = io_stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG              out_len    = io_stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID              sys_buf    = irp->AssociatedIrp.SystemBuffer;

    UNREFERENCED_PARAMETER(device_obj);

    irp->IoStatus.Information = 0;

    switch (ioctl_code)
    {
    case IOCTL_HV_STATUS:
    {
        if (out_len >= sizeof(UINT32))
        {
            *(UINT32 *)sys_buf        = g_hv_active ? g_cpu_count : 0;
            irp->IoStatus.Information = sizeof(UINT32);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_HV_INFO:
    {
        if (out_len >= sizeof(HV_INFO))
        {
            PHV_INFO info = (PHV_INFO)sys_buf;
            RtlZeroMemory(info, sizeof(HV_INFO));
            info->cpu_count  = g_cpu_count;
            info->backend    = g_hv_backend ? (UINT32)g_hv_backend->vendor : 0;
            info->maxphyaddr = g_cpu.maxphyaddr;

            if (g_ept)
            {
                if (g_ept->vpid_enabled || g_ept->npt_supported)
                    info->features |= HV_FEAT_VPID_OR_ASID;
                if (g_ept->page_table)
                    info->features |= HV_FEAT_EPT_OR_NPT;
                if (g_ept->huge_1gb_supported)
                    info->features |= HV_FEAT_1GB_PAGES;
            }
#if USE_PRIVATE_HOST_CR3
            info->features |= HV_FEAT_PRIVATE_HOST_CR3;
#endif
#if USE_PRIVATE_HOST_IDT
            if (g_host_idt.initialized)
                info->features |= HV_FEAT_PRIVATE_HOST_IDT;
#endif
#if USE_PRIVATE_HOST_GDT
            info->features |= HV_FEAT_PRIVATE_HOST_GDT;
#endif
            if (g_power_cb_reg)
                info->features |= HV_FEAT_POWER_CALLBACK;

            if (g_hv_backend)
            {
                SIZE_T len = 0;
                while (len < sizeof(info->backend_name) - 1 && g_hv_backend->name[len])
                    len++;
                RtlCopyMemory(info->backend_name, g_hv_backend->name, len);
                info->backend_name[len] = 0;
            }
            irp->IoStatus.Information = sizeof(HV_INFO);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_HV_STATS:
    {
        if (out_len >= sizeof(HV_STATS))
        {
            PHV_STATS stats = (PHV_STATS)sys_buf;
            RtlZeroMemory(stats, sizeof(HV_STATS));
            stats->cpu_count       = g_cpu_count;
            stats->min_exit_cycles = MAXULONG64;

            if (g_vcpu)
            {
                for (UINT32 i = 0; i < g_vcpu_capacity; i++)
                {
                    if (!g_vcpu[i].launched && g_vcpu[i].exit_count == 0)
                        continue;

                    stats->total_exits       += g_vcpu[i].exit_count;
                    stats->cpuid_exits       += g_vcpu[i].cpuid_exits;
                    stats->msr_exits         += g_vcpu[i].msr_exits;
                    stats->cr_exits          += g_vcpu[i].cr_exits;
                    stats->ept_npt_exits     += g_vcpu[i].ept_npt_exits;
                    stats->total_exit_cycles += g_vcpu[i].total_exit_cycles;

                    if (g_vcpu[i].min_exit_cycles < stats->min_exit_cycles)
                        stats->min_exit_cycles = g_vcpu[i].min_exit_cycles;
                    if (g_vcpu[i].max_exit_cycles > stats->max_exit_cycles)
                        stats->max_exit_cycles = g_vcpu[i].max_exit_cycles;
                }
            }

            if (stats->min_exit_cycles == MAXULONG64)
                stats->min_exit_cycles = 0;

            if (g_ept)
            {
                stats->active_watchpoints = g_ept->active_watchpoints;
                if (g_ept->page_table)
                    stats->dyn_mmio_mapped = (UINT64)g_ept->page_table->DynMappedCount;

                for (UINT32 i = 0; i < HV_MAX_WATCHPOINTS; i++)
                {
                    if (g_ept->watchpoints[i].active)
                        stats->watchpoint_hits += (UINT64)g_ept->watchpoints[i].hit_count;
                }
            }

            irp->IoStatus.Information = sizeof(HV_STATS);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_HV_DRAIN_LOGS:
    {
        if (out_len >= sizeof(HV_LOG_ENTRY))
        {
            UINT32 max_entries = out_len / sizeof(HV_LOG_ENTRY);
            UINT32 drained     = logbuf_drain((PHV_LOG_ENTRY)sys_buf, max_entries);
            irp->IoStatus.Information = (ULONG_PTR)drained * sizeof(HV_LOG_ENTRY);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_HV_FAULT_INFO:
    {
        if (out_len >= sizeof(HV_FAULT_REPORT))
        {
            PHV_FAULT_REPORT rep = (PHV_FAULT_REPORT)sys_buf;
            rep->valid      = (UINT32)g_host_fault_info.valid;
            rep->vector     = g_host_fault_info.vector;
            rep->error_code = g_host_fault_info.error_code;
            rep->rip        = g_host_fault_info.rip;
            rep->cs         = g_host_fault_info.cs;
            rep->rflags     = g_host_fault_info.rflags;
            rep->rsp        = g_host_fault_info.rsp;
            rep->cr2        = g_host_fault_info.cr2;
            irp->IoStatus.Information = sizeof(HV_FAULT_REPORT);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_HV_ADD_WATCHPOINT:
    {
        if (in_len >= sizeof(HV_WATCHPOINT_REQ))
        {
            PHV_WATCHPOINT_REQ req = (PHV_WATCHPOINT_REQ)sys_buf;
            if (!ept_add_watchpoint(req->phys_addr, req->flags))
                status = STATUS_UNSUCCESSFUL;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_HV_REMOVE_WATCHPOINT:
    {
        if (in_len >= sizeof(HV_WATCHPOINT_REQ))
        {
            PHV_WATCHPOINT_REQ req = (PHV_WATCHPOINT_REQ)sys_buf;
            if (!ept_remove_watchpoint(req->phys_addr))
                status = STATUS_NOT_FOUND;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_HV_TRACE_MSR:
    {
        if (in_len >= sizeof(HV_MSR_TRACE_REQ))
        {
            PHV_MSR_TRACE_REQ req = (PHV_MSR_TRACE_REQ)sys_buf;
            if (!hv_set_msr_trace(req->msr, req->trace_read ? TRUE : FALSE, req->trace_write ? TRUE : FALSE))
                status = STATUS_INVALID_PARAMETER;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}
