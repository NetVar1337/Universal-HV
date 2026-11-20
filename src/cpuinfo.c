/*
*   cpuinfo.c - cpu vendor detection and virtualization capability probing
*/
#include "hv.h"

CPU_CAPS g_cpu = {0};

BOOLEAN
cpuinfo_init(VOID)
{
    INT32 regs[4] = {0};
    UINT32 max_ext;

    RtlZeroMemory(&g_cpu, sizeof(g_cpu));

    //
    // vendor string: CPUID.0 EBX:EDX:ECX (compared manually — no CRT dependency)
    //
    __cpuid(regs, CPUID_MAX_STD_LEAF);
    *(UINT32 *)&g_cpu.vendor_string[0] = (UINT32)regs[1];
    *(UINT32 *)&g_cpu.vendor_string[4] = (UINT32)regs[3];
    *(UINT32 *)&g_cpu.vendor_string[8] = (UINT32)regs[2];
    g_cpu.vendor_string[12] = 0;

    {
        static const CHAR intel_str[12] = { 'G','e','n','u','i','n','e','I','n','t','e','l' };
        static const CHAR amd_str[12]   = { 'A','u','t','h','e','n','t','i','c','A','M','D' };

        if (RtlEqualMemory(g_cpu.vendor_string, intel_str, 12))
            g_cpu.vendor = HV_VENDOR_INTEL;
        else if (RtlEqualMemory(g_cpu.vendor_string, amd_str, 12))
            g_cpu.vendor = HV_VENDOR_AMD;
        else
            g_cpu.vendor = HV_VENDOR_UNKNOWN;
    }

    g_cpu.max_std_leaf = (UINT32)regs[0];

    __cpuid(regs, CPUID_EXT_MAX_LEAF);
    max_ext = g_cpu.max_ext_leaf = (UINT32)regs[0];

    //
    // hypervisor present bit (we may be a guest of Hyper-V etc.) and the
    // VMX capability bit — both from CPUID.1:ECX; capture ECX now because
    // regs is reused below.
    //
    __cpuid(regs, CPUID_VERSION_FEATURES);
    {
        UINT32 feat1_ecx = (UINT32)regs[2];
        g_cpu.hypervisor_present = !!(feat1_ecx & (1 << CPUID_HYPERVISOR_BIT));
        g_cpu.vmx_capable = !!(feat1_ecx & (1 << CPUID_VMX_BIT));
    }

    //
    // physical address width: CPUID.80000008:EAX[7:0] = MAXPHYADDR
    // (same leaf/field on Intel and AMD). default to 36 if leaf missing.
    //
    if (max_ext >= CPUID_ADDR_BITS)
    {
        __cpuid(regs, CPUID_ADDR_BITS);
        g_cpu.maxphyaddr = (UINT8)(regs[0] & 0xFF);
    }
    if (g_cpu.maxphyaddr < 36)
        g_cpu.maxphyaddr = 36;
    if (g_cpu.maxphyaddr > 52)
        g_cpu.maxphyaddr = 52;

    //
    // vendor-specific virtualization capability
    //
    if (g_cpu.vendor == HV_VENDOR_INTEL)
    {
        g_cpu.feature_control.AsUInt = __readmsr(IA32_FEATURE_CONTROL);
    }
    else if (g_cpu.vendor == HV_VENDOR_AMD)
    {
        if (max_ext >= CPUID_EXT_FEATURES)
        {
            __cpuid(regs, CPUID_EXT_FEATURES);
            g_cpu.svm_capable = !!(regs[2] & (1 << CPUID_SVM_BIT));
        }
        if (max_ext >= CPUID_SVM_INFO)
        {
            __cpuid(regs, CPUID_SVM_INFO);
            g_cpu.svm_features  = (UINT32)regs[3];
            g_cpu.svm_num_asids = (UINT32)regs[1];
        }
        if (g_cpu.svm_capable)
            g_cpu.vm_cr = __readmsr(MSR_VM_CR);
    }

    DbgPrintEx(0, 0,
             "[hv] cpu: %s maxphyaddr=%u hypervisor_present=%d vmx=%d svm=%d svm_feat=0x%x asids=%u\n",
             g_cpu.vendor_string, g_cpu.maxphyaddr, g_cpu.hypervisor_present,
             g_cpu.vmx_capable, g_cpu.svm_capable, g_cpu.svm_features, g_cpu.svm_num_asids);

    return TRUE;
}

BOOLEAN
cpuinfo_vmx_enable(VOID)
{
    IA32_FEATURE_CONTROL_REGISTER fc;

    if (g_cpu.vendor != HV_VENDOR_INTEL || !g_cpu.vmx_capable)
        return FALSE;

    fc.AsUInt = __readmsr(IA32_FEATURE_CONTROL);

    if (!fc.Lock)
    {
        //
        // firmware left FEATURE_CONTROL unlocked: enable VMX outside SMX
        // ourselves and lock it, exactly like an OS would. this fixes
        // machines whose BIOS does not lock the MSR.
        //
        fc.EnableVmxOutsideSmx = 1;
        fc.Lock = 1;
        __writemsr(IA32_FEATURE_CONTROL, fc.AsUInt);
    }

    g_cpu.feature_control = fc;
    g_cpu.vmx_usable = (fc.Lock && fc.EnableVmxOutsideSmx) ? TRUE : FALSE;

    if (!g_cpu.vmx_usable)
    {
        //
        // locked with VMX-outside-SMX disabled: VT-x is off in firmware,
        // or another hypervisor (Hyper-V) already owns VMX. fail cleanly.
        //
        DbgPrintEx(0, 0, "[hv] VMX not usable (FEATURE_CONTROL=0x%llx) — VT-x disabled in BIOS or owned by another hypervisor\n",
                 fc.AsUInt);
    }

    return g_cpu.vmx_usable;
}

BOOLEAN
cpuinfo_svm_check(VOID)
{
    if (g_cpu.vendor != HV_VENDOR_AMD || !g_cpu.svm_capable)
        return FALSE;

    //
    // VM_CR.SVM_DIS set => BIOS locked SVM off (some OEMs ship this way).
    //
    if (g_cpu.vm_cr & VM_CR_SVM_DIS)
    {
        DbgPrintEx(0, 0, "[hv] SVM present but locked off by firmware (VM_CR=0x%llx)\n", g_cpu.vm_cr);
        return FALSE;
    }

    g_cpu.svm_usable = TRUE;
    return TRUE;
}
