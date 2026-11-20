/*
*   driver.c - windows kernel driver entry point for the hypervisor
*   creates a device object, symbolic link, and initializes the backend
*   (Intel VMX or AMD SVM, selected from the CPU vendor) provides ioctl
*   interface for usermode loader communication
*/
#include "hv.h"

#define DEVICE_NAME     L"\\Device\\Ophion"
#define SYMLINK_NAME    L"\\DosDevices\\Ophion"

#define IOCTL_BASE      0x800
#define IOCTL_HV_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_INFO   CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// HV_INFO returned by IOCTL_HV_INFO
//
typedef struct _HV_INFO {
    UINT32 cpu_count;       // logical processors virtualized (all groups)
    UINT32 backend;         // HV_VENDOR of the active backend
    UINT32 maxphyaddr;
    UINT32 _reserved;
    CHAR   backend_name[16];
} HV_INFO, *PHV_INFO;

static NTSTATUS DriverCreateClose(PDEVICE_OBJECT device_obj, PIRP irp);
static NTSTATUS DriverIoControl(PDEVICE_OBJECT device_obj, PIRP irp);

VOID
DriverUnload(_In_ PDRIVER_OBJECT driver_obj)
{
    UNICODE_STRING symlink;

    DbgPrintEx(0, 0, "[hv] Unloading hypervisor driver...\n");

    //
    // only broadcast the terminate VMCALL/VMMCALL if the hypervisor actually
    // virtualized the processors — issuing it on a non-virtualized cpu #UDs.
    //
    if (g_hv_active)
        broadcast_terminate_all();

    if (g_hv_backend)
        g_hv_backend->terminate();

    g_hv_active = FALSE;

    RtlInitUnicodeString(&symlink, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink);

    if (driver_obj->DeviceObject)
    {
        IoDeleteDevice(driver_obj->DeviceObject);
    }

    DbgPrintEx(0, 0, "[hv] Driver unloaded.\n");
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

    DbgPrintEx(0, 0, "[hv] Ophion initializing...\n");

    //
    // version-compatibility layer first (resolves ExAllocatePool2 etc.)
    //
    win_compat_init();

    //
    // detect CPU vendor and pick the virtualization backend:
    //   Intel -> VMX, AMD -> SVM
    //
    cpuinfo_init();

    if (g_cpu.vendor == HV_VENDOR_INTEL && cpuinfo_vmx_enable())
        g_hv_backend = &g_vmx_backend;
    else if (g_cpu.vendor == HV_VENDOR_AMD && cpuinfo_svm_check())
        g_hv_backend = &g_svm_backend;

    if (!g_hv_backend)
    {
        DbgPrintEx(0, 0,
                 "[hv] No usable hardware virtualization on this machine "
                 "(vendor=%d vmx=%d svm=%d). VT-x/SVM disabled in firmware or owned "
                 "by another hypervisor (Hyper-V/VBS).\n",
                 g_cpu.vendor, g_cpu.vmx_capable, g_cpu.svm_capable);
        return STATUS_NOT_SUPPORTED;
    }

    DbgPrintEx(0, 0, "[hv] Backend: %s\n", g_hv_backend->name);

    RtlInitUnicodeString(&device_name, DEVICE_NAME);
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
        DbgPrintEx(0, 0, "[hv] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }

    RtlInitUnicodeString(&symlink, SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlink, &device_name);

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(0, 0, "[hv] IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(device_obj);
        return status;
    }

    driver_obj->DriverUnload                         = DriverUnload;
    driver_obj->MajorFunction[IRP_MJ_CREATE]         = DriverCreateClose;
    driver_obj->MajorFunction[IRP_MJ_CLOSE]          = DriverCreateClose;
    driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoControl;

    if (!g_hv_backend->check_support() || !g_hv_backend->init())
    {
        DbgPrintEx(0, 0, "[hv] Hypervisor initialization FAILED!\n");
        //
        // no broadcast here: some/all cpus may not be virtualized, and the
        // terminate VMCALL/VMMCALL would #UD on them. the per-cpu DPC checks
        // the launched flag, so a broadcast is safe — but only free resources.
        //
        g_hv_backend->terminate();
        IoDeleteSymbolicLink(&symlink);
        IoDeleteDevice(device_obj);
        g_hv_backend = NULL;
        return STATUS_HV_OPERATION_FAILED;
    }

    g_hv_active = TRUE;

    DbgPrintEx(0, 0, "[hv] Hypervisor (%s) loaded and active on all %u logical processors!\n",
             g_hv_backend->name, g_cpu_count);
    return STATUS_SUCCESS;
}

static NTSTATUS
DriverCreateClose(
    _In_ PDEVICE_OBJECT device_obj,
    _In_ PIRP           irp)
{
    UNREFERENCED_PARAMETER(device_obj);

    irp->IoStatus.Status      = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
DriverIoControl(
    _In_ PDEVICE_OBJECT device_obj,
    _In_ PIRP           irp)
{
    NTSTATUS           status = STATUS_SUCCESS;
    PIO_STACK_LOCATION io_stack;
    ULONG              ioctl_code;

    UNREFERENCED_PARAMETER(device_obj);

    io_stack   = IoGetCurrentIrpStackLocation(irp);
    ioctl_code = io_stack->Parameters.DeviceIoControl.IoControlCode;

    switch (ioctl_code)
    {
    case IOCTL_HV_STATUS:
    {
        //
        // return basic status: number of virtualized logical processors
        //
        if (io_stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(UINT32))
        {
            *(UINT32 *)irp->AssociatedIrp.SystemBuffer = g_cpu_count;
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
        if (io_stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(HV_INFO))
        {
            PHV_INFO info = (PHV_INFO)irp->AssociatedIrp.SystemBuffer;
            RtlZeroMemory(info, sizeof(HV_INFO));
            info->cpu_count   = g_cpu_count;
            info->backend     = g_hv_backend ? (UINT32)g_hv_backend->vendor : 0;
            info->maxphyaddr  = g_cpu.maxphyaddr;
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

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}
