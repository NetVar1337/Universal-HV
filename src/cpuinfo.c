/*
*   cpuinfo.c - cpu vendor detection and virtualization capability probing
*/
#include "hv.h"

CPU_CAPS g_cpu = {0};

static UINT64
cpuinfo_compute_valid_cr4_mask(VOID)
{
    INT32  regs[4] = {0};
    UINT64 mask = 0;

    //
    // baseline x86-64 architectural CR4 bits always valid in 64-bit mode:
    // VME(0), PVI(1), TSD(2), DE(3), PSE(4), PAE(5), MCE(6), PGE(7),
    // PCE(8), OSFXSR(9), OSXMMEXCPT(10)
    //
    mask |= 0x07FFULL;

    //
    // CPUID.1:ECX/EDX features
    //
    if (g_cpu.max_std_leaf >= 1)
    {
        __cpuidex(regs, 1, 0);
        UINT32 ecx = (UINT32)regs[2];

        if (ecx & (1U << 5))  mask |= (1ULL << 13); // VMXE
        if (ecx & (1U << 6))  mask |= (1ULL << 14); // SMXE
        if (ecx & (1U << 17)) mask |= (1ULL << 17); // PCIDE
        if (ecx & (1U << 26)) mask |= (1ULL << 18); // OSXSAVE
    }

    //
    // CPUID.7.0:EBX/ECX/EDX features
    //
    if (g_cpu.max_std_leaf >= 7)
    {
        __cpuidex(regs, 7, 0);
        UINT32 ebx = (UINT32)regs[1];
        UINT32 ecx = (UINT32)regs[2];
        UINT32 edx = (UINT32)regs[3];

        if (ebx & (1U << 0))  mask |= (1ULL << 16); // FSGSBASE
        if (ebx & (1U << 7))  mask |= (1ULL << 20); // SMEP
        if (ebx & (1U << 20)) mask |= (1ULL << 21); // SMAP
        if (ecx & (1U << 2))  mask |= (1ULL << 11); // UMIP
        if (ecx & (1U << 3))  mask |= (1ULL << 22); // PKE
        if (ecx & (1U << 7))  mask |= (1ULL << 23); // CET
        if (ecx & (1U << 16)) mask |= (1ULL << 12); // LA57
        if (ecx & (1U << 31)) mask |= (1ULL << 24); // PKS
        if (edx & (1U << 14)) mask |= (1ULL << 25); // UINTR (if present)

        //
        // CPUID.7.1:EAX bit 26 = LAM -> CR4.LAM_SUP (bit 28)
        //
        if ((UINT32)regs[0] >= 1)
        {
            __cpuidex(regs, 7, 1);
            if ((UINT32)regs[0] & (1U << 26))
                mask |= (1ULL << 28); // LAM_SUP
            if ((UINT32)regs[0] & (1U << 17))
                mask |= (1ULL << 32); // FRED (if present)
        }
    }

    //
    // preserve any bit already set in the live host CR4
    //
    mask |= __readcr4();

    return mask;
}

BOOLEAN
cpuinfo_init(VOID)
{
    INT32  regs[4] = {0};
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

    __cpuid(regs, CPUID_VERSION_FEATURES);
    {
        UINT32 feat1_ecx = (UINT32)regs[2];
        g_cpu.hypervisor_present = !!(feat1_ecx & (1U << CPUID_HYPERVISOR_BIT));
        g_cpu.vmx_capable        = !!(feat1_ecx & (1U << CPUID_VMX_BIT));
    }

    //
    // physical address width: CPUID.80000008:EAX[7:0] = MAXPHYADDR
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

    g_cpu.cr4_valid_mask = cpuinfo_compute_valid_cr4_mask();

    //
    // vendor-specific virtualization capability + PMU counter counts
    //
    if (g_cpu.vendor == HV_VENDOR_INTEL)
    {
        g_cpu.feature_control.AsUInt = __readmsr(IA32_FEATURE_CONTROL);

        if (g_cpu.max_std_leaf >= 0x0A)
        {
            __cpuidex(regs, 0x0A, 0);
            UINT8 pmu_ver = (UINT8)(regs[0] & 0xFF);
            if (pmu_ver >= 1)
                g_cpu.pmu_gp_counters = (UINT8)((regs[0] >> 8) & 0xFF);
            if (pmu_ver >= 2)
                g_cpu.pmu_fixed_counters = (UINT8)(regs[3] & 0x1F);
        }
    }
    else if (g_cpu.vendor == HV_VENDOR_AMD)
    {
        if (max_ext >= CPUID_EXT_FEATURES)
        {
            __cpuid(regs, CPUID_EXT_FEATURES);
            g_cpu.svm_capable = !!(regs[2] & (1U << CPUID_SVM_BIT));
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

    HV_LOG("cpu: %s maxphyaddr=%u hv=%d vmx=%d svm=%d svm_feat=0x%x asids=%u pmu=%u/%u cr4_mask=0x%llx\n",
           g_cpu.vendor_string, g_cpu.maxphyaddr, g_cpu.hypervisor_present,
           g_cpu.vmx_capable, g_cpu.svm_capable, g_cpu.svm_features, g_cpu.svm_num_asids,
           g_cpu.pmu_gp_counters, g_cpu.pmu_fixed_counters, g_cpu.cr4_valid_mask);

    return TRUE;
}

BOOLEAN
cpuinfo_vmx_enable_current_cpu(VOID)
{
    IA32_FEATURE_CONTROL_REGISTER fc;

    if (g_cpu.vendor != HV_VENDOR_INTEL || !g_cpu.vmx_capable)
        return FALSE;

    fc.AsUInt = __readmsr(IA32_FEATURE_CONTROL);

    if (!fc.Lock)
    {
        //
        // firmware left FEATURE_CONTROL unlocked on this logical processor:
        // enable VMX outside SMX and lock it.
        //
        fc.EnableVmxOutsideSmx = 1;
        fc.Lock = 1;
        __writemsr(IA32_FEATURE_CONTROL, fc.AsUInt);
        fc.AsUInt = __readmsr(IA32_FEATURE_CONTROL);
    }

    return (fc.Lock && fc.EnableVmxOutsideSmx) ? TRUE : FALSE;
}

BOOLEAN
cpuinfo_vmx_enable(VOID)
{
    BOOLEAN ok = cpuinfo_vmx_enable_current_cpu();

    if (g_cpu.vendor == HV_VENDOR_INTEL && g_cpu.vmx_capable)
        g_cpu.feature_control.AsUInt = __readmsr(IA32_FEATURE_CONTROL);

    g_cpu.vmx_usable = ok;

    if (!ok)
    {
        HV_LOG("VMX not usable (FEATURE_CONTROL=0x%llx) — VT-x disabled in BIOS or owned by another hypervisor\n",
               g_cpu.feature_control.AsUInt);
    }

    return ok;
}

BOOLEAN
cpuinfo_svm_check(VOID)
{
    if (g_cpu.vendor != HV_VENDOR_AMD || !g_cpu.svm_capable)
        return FALSE;

    //
    // VM_CR.SVMDIS (bit 4) set => BIOS locked SVM off.
    //
    if (g_cpu.vm_cr & VM_CR_SVM_DIS)
    {
        HV_LOG("SVM present but locked off by firmware (VM_CR=0x%llx)\n", g_cpu.vm_cr);
        return FALSE;
    }

    g_cpu.svm_usable = TRUE;
    return TRUE;
}
