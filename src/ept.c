/*
*   ept.c - extended page tables (Intel EPT) / nested paging (AMD NPT)
*
*   builds a shared identity-mapped page table (guest physical == host
*   physical) covering:
*     - the low 4GB always (RAM + MMIO holes below 4GB)
*     - every RAM range reported by MmGetPhysicalMemoryRanges
*     - dynamic on-demand UC mapping from a pre-allocated root-mode page pool
*       for above-4G MMIO (e.g. 64-bit PCIe BARs / Resizable BAR)
*
*   Intel builds true Intel EPT entries (R/W/X + EPT MemoryType in bits 5:3).
*   AMD builds true x86-64 NPT entries (P/RW/US + PAT/PCD/PWT derived from
*   IA32_PAT), never reusing EPT bit layouts on AMD.
*/
#include "hv.h"

#define EPT_MAX_PHYS_SUPPORTED   (1ULL << 48)   // 4-level walk limit

BOOLEAN
ept_is_npt_mode(VOID)
{
    return (g_ept && g_ept->is_npt) ? TRUE : FALSE;
}

static VOID
ept_init_npt_pat_map(VOID)
{
    UINT64 pat = __readmsr(IA32_PAT);
    UINT8  uc_idx = 3; // default architectural PAT index 3 = UC

    //
    // find an index encoding UC first as a safe fallback
    //
    for (UINT8 idx = 0; idx < 8; idx++)
    {
        UINT8 type = (UINT8)((pat >> (idx * 8)) & 0xFF);
        if (type == MEMORY_TYPE_UNCACHEABLE)
        {
            uc_idx = idx;
            break;
        }
    }

    for (UINT32 mt = 0; mt < 8; mt++)
        g_ept->npt_pat_index[mt] = uc_idx;

    for (UINT8 idx = 0; idx < 8; idx++)
    {
        UINT8 type = (UINT8)((pat >> (idx * 8)) & 0xFF);
        if (type < 8 && g_ept->npt_pat_index[type] == uc_idx)
            g_ept->npt_pat_index[type] = idx;
    }

    //
    // ensure UC itself maps to uc_idx
    //
    g_ept->npt_pat_index[MEMORY_TYPE_UNCACHEABLE] = uc_idx;
}

static __forceinline UINT64
npt_pat_bits(UINT8 mem_type, BOOLEAN is_2mb)
{
    UINT8  idx = (mem_type < 8) ? g_ept->npt_pat_index[mem_type] : g_ept->npt_pat_index[MEMORY_TYPE_UNCACHEABLE];
    UINT64 bits = 0;

    if (idx & 1U) bits |= NPT_PTE_PWT;
    if (idx & 2U) bits |= NPT_PTE_PCD;
    if (idx & 4U) bits |= (is_2mb ? NPT_PTE_PAT_2M : NPT_PTE_PAT_4K);
    return bits;
}

static __forceinline UINT64
ept_make_nonleaf(UINT64 next_pa)
{
    if (g_ept->is_npt)
    {
        return NPT_PTE_PRESENT | NPT_PTE_WRITE | NPT_PTE_USER | (next_pa & NPT_PTE_PFN_MASK);
    }
    else
    {
        EPT_PML4_ENTRY e = {0};
        e.ReadAccess      = 1;
        e.WriteAccess     = 1;
        e.ExecuteAccess   = 1;
        e.PageFrameNumber = next_pa / PAGE_SIZE;
        return e.AsUInt;
    }
}

static __forceinline UINT64
ept_make_leaf_1gb(SIZE_T pfn1gb, UINT8 mem_type)
{
    if (g_ept->is_npt)
    {
        return NPT_PTE_PRESENT | NPT_PTE_WRITE | NPT_PTE_USER | NPT_PTE_LARGE_PAGE |
               (((UINT64)pfn1gb) << 30) | npt_pat_bits(mem_type, TRUE);
    }
    else
    {
        EPT_PML3_ENTRY e = {0};
        e.ReadAccess      = 1;
        e.WriteAccess     = 1;
        e.ExecuteAccess   = 1;
        e.LargePage       = 1;
        e.MemoryType      = mem_type;
        e.PageFrameNumber = (UINT64)pfn1gb;
        return e.AsUInt;
    }
}

static __forceinline UINT64
ept_make_leaf_2mb(SIZE_T pfn2mb, UINT8 mem_type)
{
    if (g_ept->is_npt)
    {
        return NPT_PTE_PRESENT | NPT_PTE_WRITE | NPT_PTE_USER | NPT_PTE_LARGE_PAGE |
               (((UINT64)pfn2mb) << 21) | npt_pat_bits(mem_type, TRUE);
    }
    else
    {
        EPT_PML2_ENTRY e = {0};
        e.ReadAccess      = 1;
        e.WriteAccess     = 1;
        e.ExecuteAccess   = 1;
        e.LargePage       = 1;
        e.MemoryType      = mem_type;
        e.PageFrameNumber = (UINT64)pfn2mb;
        return e.AsUInt;
    }
}

static __forceinline UINT64
ept_make_leaf_4kb(SIZE_T pfn4k, UINT8 mem_type)
{
    if (g_ept->is_npt)
    {
        return NPT_PTE_PRESENT | NPT_PTE_WRITE | NPT_PTE_USER |
               (((UINT64)pfn4k) << 12) | npt_pat_bits(mem_type, FALSE);
    }
    else
    {
        EPT_PML1_ENTRY e = {0};
        e.ReadAccess      = 1;
        e.WriteAccess     = 1;
        e.ExecuteAccess   = 1;
        e.MemoryType      = mem_type;
        e.PageFrameNumber = (UINT64)pfn4k;
        return e.AsUInt;
    }
}

static __forceinline BOOLEAN
ept_entry_is_present(UINT64 raw)
{
    // bit 0 is ReadAccess on Intel EPT and Present on AMD NPT
    return (raw & 1ULL) ? TRUE : FALSE;
}

static __forceinline BOOLEAN
ept_entry_is_large(UINT64 raw)
{
    // bit 7 is LargePage on Intel EPT PDE and PS on AMD NPT PDE
    return (raw & (1ULL << 7)) ? TRUE : FALSE;
}

static __forceinline UINT64
ept_entry_next_pa(UINT64 raw)
{
    return raw & NPT_PTE_PFN_MASK;
}

//
// root-mode-safe PA->VA lookup using tracked EPT/NPT page table entries
// (ZERO Windows API calls — safe inside VMX-root / SVM host mode).
//
static PVOID
ept_tracked_pa_to_va(PVMM_EPT_PAGE_TABLE table, UINT64 pa)
{
    UINT64 target = pa & ~0xFFFULL;

    if (target == table->PML4_Pa)
        return table->PML4_Page;

    for (UINT32 i = 0; i < table->TrackedCount; i++)
    {
        if (table->Tracked[i].Pa == target)
            return table->Tracked[i].Va;
    }

    for (UINT32 i = 0; i < table->DynPoolUsed; i++)
    {
        if (table->DynPool[i].Pa == target)
            return table->DynPool[i].Va;
    }

    return NULL;
}

BOOLEAN
ept_check_features(VOID)
{
    IA32_MTRR_DEF_TYPE_REGISTER mtrr_def;

    mtrr_def.AsUInt = __readmsr(IA32_MTRR_DEF_TYPE);

    if (g_cpu.vendor == HV_VENDOR_INTEL)
    {
        IA32_VMX_EPT_VPID_CAP_REGISTER vpid_reg;

        g_ept->is_npt = FALSE;
        vpid_reg.AsUInt = __readmsr(IA32_VMX_EPT_VPID_CAP);

        if (!vpid_reg.PageWalkLength4 || !vpid_reg.MemoryTypeWriteBack || !vpid_reg.Pde2MbPages)
        {
            HV_LOG("EPT: missing required features (PW4=%d WB=%d 2MB=%d)\n",
                   vpid_reg.PageWalkLength4, vpid_reg.MemoryTypeWriteBack, vpid_reg.Pde2MbPages);
            return FALSE;
        }

        g_ept->ad_supported       = vpid_reg.EptAccessedAndDirtyFlags ? TRUE : FALSE;
        g_ept->huge_1gb_supported = vpid_reg.Pdpte1GbPages ? TRUE : FALSE;

        g_ept->invvpid_supported                = vpid_reg.Invvpid ? TRUE : FALSE;
        g_ept->invvpid_individual_addr          = vpid_reg.InvvpidIndividualAddress ? TRUE : FALSE;
        g_ept->invvpid_single_context           = vpid_reg.InvvpidSingleContext ? TRUE : FALSE;
        g_ept->invvpid_all_contexts             = vpid_reg.InvvpidAllContexts ? TRUE : FALSE;
        g_ept->invvpid_single_retaining_globals = vpid_reg.InvvpidSingleContextRetainingGlobals ? TRUE : FALSE;

        {
            IA32_VMX_BASIC_REGISTER vmx_basic = {0};
            MSR msr = {0};
            vmx_basic.AsUInt = __readmsr(IA32_VMX_BASIC);
            msr.Flags = __readmsr(vmx_basic.VmxControls ? IA32_VMX_TRUE_PROCBASED_CTLS
                                                        : IA32_VMX_PROCBASED_CTLS);
            if (!(msr.Fields.High & CPU_BASED_VM_EXEC_CTRL_ACTIVATE_SECONDARY_CONTROLS))
            {
                HV_LOG("EPT: secondary controls not supported — CPU too old\n");
                return FALSE;
            }
            msr.Flags = __readmsr(IA32_VMX_PROCBASED_CTLS2);
            if (!(msr.Fields.High & CPU_BASED_VM_EXEC_CTRL2_ENABLE_EPT))
            {
                HV_LOG("EPT: ENABLE_EPT not supported on this CPU\n");
                return FALSE;
            }
        }

        HV_LOG("INVVPID caps: supported=%d individual=%d single=%d all=%d retaining=%d\n",
               g_ept->invvpid_supported,
               g_ept->invvpid_individual_addr,
               g_ept->invvpid_single_context,
               g_ept->invvpid_all_contexts,
               g_ept->invvpid_single_retaining_globals);
    }
    else if (g_cpu.vendor == HV_VENDOR_AMD)
    {
        g_ept->is_npt        = TRUE;
        g_ept->npt_supported = (g_cpu.svm_features & SVM_FEATURE_NP) ? TRUE : FALSE;
        if (!g_ept->npt_supported)
        {
            HV_LOG("NPT: nested paging not supported on this CPU\n");
            return FALSE;
        }
        //
        // Check 1GB page support via CPUID.80000001:EDX[26] (Page1GB)
        //
        if (g_cpu.max_ext_leaf >= CPUID_EXT_FEATURES)
        {
            INT32 regs[4] = {0};
            __cpuid(regs, CPUID_EXT_FEATURES);
            g_ept->huge_1gb_supported = ((UINT32)regs[3] & (1U << 26)) ? TRUE : FALSE;
        }
        ept_init_npt_pat_map();
    }

    if (!mtrr_def.MtrrEnable)
    {
        HV_LOG("EPT/NPT: MTRR not enabled, defaulting to UC\n");
        g_ept->default_type = MEMORY_TYPE_UNCACHEABLE;
    }

    return TRUE;
}

static BOOLEAN
ept_addr_in_ram(UINT64 addr)
{
    for (UINT32 i = 0; i < g_ept->num_ram_ranges; i++)
    {
        if (addr >= g_ept->ram_ranges[i].base && addr <= g_ept->ram_ranges[i].end)
            return TRUE;
    }
    return FALSE;
}

UINT8
ept_get_memory_type(SIZE_T pfn, BOOLEAN is_large_page)
{
    UINT64 page_addr   = is_large_page ? ((UINT64)pfn * SIZE_2_MB) : ((UINT64)pfn * PAGE_SIZE);
    UINT8  target_type = (UINT8)-1;

    //
    // non-RAM (MMIO holes, firmware areas): uncacheable unless a fixed-range
    // MTRR (low 1MB) explicitly types it.
    //
    if (!ept_addr_in_ram(page_addr))
    {
        for (UINT32 i = 0; i < g_ept->num_ranges; i++)
        {
            MTRR_RANGE_DESCRIPTOR * range = &g_ept->mem_ranges[i];
            if (range->fixed &&
                page_addr >= range->phys_base && page_addr <= range->phys_end)
                return range->mem_type;
        }
        return MEMORY_TYPE_UNCACHEABLE;
    }

    //
    // Intel SDM Vol 3 Section 11.11.4.1 (MTRR Precedences):
    //   1. Fixed-range MTRRs take precedence over variable-range MTRRs.
    //   2. Among overlapping variable-range MTRRs:
    //      - If ANY overlapping range is UC, effective type is UC.
    //      - If overlapping ranges are WT and WB, effective type is WT.
    //
    for (UINT32 i = 0; i < g_ept->num_ranges; i++)
    {
        MTRR_RANGE_DESCRIPTOR * range = &g_ept->mem_ranges[i];

        if (page_addr >= range->phys_base && page_addr <= range->phys_end)
        {
            if (range->fixed)
            {
                target_type = range->mem_type;
                break;
            }

            if (range->mem_type == MEMORY_TYPE_UNCACHEABLE)
            {
                target_type = MEMORY_TYPE_UNCACHEABLE;
                break;
            }

            if (target_type == (UINT8)-1)
            {
                target_type = range->mem_type;
            }
            else if ((target_type == MEMORY_TYPE_WRITE_THROUGH && range->mem_type == MEMORY_TYPE_WRITE_BACK) ||
                     (target_type == MEMORY_TYPE_WRITE_BACK && range->mem_type == MEMORY_TYPE_WRITE_THROUGH))
            {
                target_type = MEMORY_TYPE_WRITE_THROUGH;
            }
            else if (range->mem_type != target_type)
            {
                //
                // undefined overlap per SDM — safest architectural choice is UC
                //
                target_type = MEMORY_TYPE_UNCACHEABLE;
                break;
            }
        }
    }

    if (target_type == (UINT8)-1)
        target_type = g_ept->default_type;

    return target_type;
}

BOOLEAN
ept_build_mtrr_map(VOID)
{
    IA32_MTRR_CAPABILITIES_REGISTER mtrr_cap;
    IA32_MTRR_DEF_TYPE_REGISTER     mtrr_def;
    IA32_MTRR_PHYSBASE_REGISTER     cur_base;
    IA32_MTRR_PHYSMASK_REGISTER     cur_mask;
    MTRR_RANGE_DESCRIPTOR *         desc;

    mtrr_cap.AsUInt = __readmsr(IA32_MTRR_CAPABILITIES);
    mtrr_def.AsUInt = __readmsr(IA32_MTRR_DEF_TYPE);

    if (mtrr_def.MtrrEnable)
        g_ept->default_type = (UINT8)mtrr_def.DefaultMemoryType;
    else
        g_ept->default_type = MEMORY_TYPE_UNCACHEABLE;

    //
    // fixed-range mtrrs (64K, 16K, 4K regions of the low 1MB)
    //
    if (mtrr_cap.FixedRangeSupported && mtrr_def.FixedRangeMtrrEnable)
    {
        IA32_MTRR_FIXED_RANGE_TYPE k64_types = { __readmsr(IA32_MTRR_FIX64K_00000) };
        for (UINT32 i = 0; i < 8 && g_ept->num_ranges < MAX_MTRR_RANGES; i++)
        {
            desc = &g_ept->mem_ranges[g_ept->num_ranges++];
            desc->mem_type  = k64_types.s.Types[i];
            desc->phys_base = 0x10000ULL * i;
            desc->phys_end  = desc->phys_base + 0x10000ULL - 1ULL;
            desc->fixed     = TRUE;
        }

        for (UINT32 i = 0; i < 2 && g_ept->num_ranges < MAX_MTRR_RANGES; i++)
        {
            IA32_MTRR_FIXED_RANGE_TYPE k16_types = { __readmsr(IA32_MTRR_FIX16K_80000 + i) };
            for (UINT32 j = 0; j < 8 && g_ept->num_ranges < MAX_MTRR_RANGES; j++)
            {
                desc = &g_ept->mem_ranges[g_ept->num_ranges++];
                desc->mem_type  = k16_types.s.Types[j];
                desc->phys_base = 0x80000ULL + ((UINT64)i * 0x20000ULL) + ((UINT64)j * 0x4000ULL);
                desc->phys_end  = desc->phys_base + 0x4000ULL - 1ULL;
                desc->fixed     = TRUE;
            }
        }

        for (UINT32 i = 0; i < 8 && g_ept->num_ranges < MAX_MTRR_RANGES; i++)
        {
            IA32_MTRR_FIXED_RANGE_TYPE k4_types = { __readmsr(IA32_MTRR_FIX4K_C0000 + i) };
            for (UINT32 j = 0; j < 8 && g_ept->num_ranges < MAX_MTRR_RANGES; j++)
            {
                desc = &g_ept->mem_ranges[g_ept->num_ranges++];
                desc->mem_type  = k4_types.s.Types[j];
                desc->phys_base = 0xC0000ULL + ((UINT64)i * 0x8000ULL) + ((UINT64)j * 0x1000ULL);
                desc->phys_end  = desc->phys_base + 0x1000ULL - 1ULL;
                desc->fixed     = TRUE;
            }
        }
    }

    //
    // variable-range mtrrs
    //
    for (UINT32 i = 0; i < mtrr_cap.VariableRangeCount && g_ept->num_ranges < MAX_MTRR_RANGES; i++)
    {
        cur_base.AsUInt = __readmsr(IA32_MTRR_PHYSBASE0 + (i * 2));
        cur_mask.AsUInt = __readmsr(IA32_MTRR_PHYSMASK0 + (i * 2));

        if (cur_mask.Valid)
        {
            ULONG mask_bits = 0;
            UINT64 mask_val = cur_mask.PageFrameNumber * PAGE_SIZE;
            if (!mask_val || !_BitScanForward64(&mask_bits, mask_val))
                continue;

            desc = &g_ept->mem_ranges[g_ept->num_ranges++];
            desc->phys_base = cur_base.PageFrameNumber * PAGE_SIZE;
            desc->phys_end  = desc->phys_base + ((1ULL << mask_bits) - 1ULL);
            desc->mem_type  = (UINT8)cur_base.Type;
            desc->fixed     = FALSE;
        }
    }

    //
    // physical RAM ranges
    //
    {
        PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
        if (ranges)
        {
            for (UINT32 i = 0; ranges[i].BaseAddress.QuadPart != 0 || ranges[i].NumberOfBytes.QuadPart != 0; i++)
            {
                if (g_ept->num_ram_ranges >= MAX_RAM_RANGES)
                    break;
                if (ranges[i].NumberOfBytes.QuadPart == 0)
                    continue;
                g_ept->ram_ranges[g_ept->num_ram_ranges].base = (UINT64)ranges[i].BaseAddress.QuadPart;
                g_ept->ram_ranges[g_ept->num_ram_ranges].end  =
                    (UINT64)ranges[i].BaseAddress.QuadPart + (UINT64)ranges[i].NumberOfBytes.QuadPart - 1ULL;
                g_ept->num_ram_ranges++;
            }
            ExFreePool(ranges);
        }
    }

    HV_LOG("EPT/NPT: %u MTRR ranges, %u RAM ranges, maxphyaddr=%u, mode=%s\n",
           g_ept->num_ranges, g_ept->num_ram_ranges, g_ept->maxphyaddr,
           g_ept->is_npt ? "AMD-NPT" : "Intel-EPT");

    return TRUE;
}

BOOLEAN
ept_valid_for_large_page(SIZE_T pfn2mb)
{
    UINT64 start_addr = (UINT64)pfn2mb * SIZE_2_MB;
    UINT64 end_addr   = start_addr + SIZE_2_MB - 1ULL;

    //
    // must not cross or partially overlap any MTRR boundary
    //
    for (UINT32 i = 0; i < g_ept->num_ranges; i++)
    {
        MTRR_RANGE_DESCRIPTOR * range = &g_ept->mem_ranges[i];

        if ((start_addr <= range->phys_end && end_addr > range->phys_end) ||
            (start_addr < range->phys_base && end_addr >= range->phys_base))
        {
            return FALSE;
        }
    }

    //
    // must not cross or partially contain ANY RAM/non-RAM boundary
    // (catches small MMIO holes strictly inside the 2MB chunk too!)
    //
    for (UINT32 i = 0; i < g_ept->num_ram_ranges; i++)
    {
        RAM_RANGE * ram = &g_ept->ram_ranges[i];

        if ((start_addr <= ram->end && end_addr > ram->end) ||
            (start_addr < ram->base && end_addr >= ram->base))
        {
            return FALSE;
        }
    }

    return TRUE;
}

BOOLEAN
ept_valid_for_1gb_page(SIZE_T pfn1gb)
{
    UINT64 start_addr = (UINT64)pfn1gb * SIZE_1_GB;
    UINT64 end_addr   = start_addr + SIZE_1_GB - 1ULL;

    for (UINT32 i = 0; i < g_ept->num_ranges; i++)
    {
        MTRR_RANGE_DESCRIPTOR * range = &g_ept->mem_ranges[i];
        if ((start_addr <= range->phys_end && end_addr > range->phys_end) ||
            (start_addr < range->phys_base && end_addr >= range->phys_base))
        {
            return FALSE;
        }
    }

    for (UINT32 i = 0; i < g_ept->num_ram_ranges; i++)
    {
        RAM_RANGE * ram = &g_ept->ram_ranges[i];
        if ((start_addr <= ram->end && end_addr > ram->end) ||
            (start_addr < ram->base && end_addr >= ram->base))
        {
            return FALSE;
        }
    }

    return TRUE;
}

static PVOID
ept_alloc_table(PVMM_EPT_PAGE_TABLE table, UINT64 *pa_out)
{
    if (table->TrackedCount >= EPT_MAX_TRACKED_PAGES)
        return NULL;

    PVOID page = hv_alloc_contiguous(PAGE_SIZE);
    if (!page)
        return NULL;

    RtlZeroMemory(page, PAGE_SIZE);
    UINT64 pa = va_to_pa(page);

    table->Tracked[table->TrackedCount].Va = page;
    table->Tracked[table->TrackedCount].Pa = pa;
    table->TrackedCount++;

    if (pa_out)
        *pa_out = pa;
    return page;
}

static PVOID
ept_ensure_pml3(PVMM_EPT_PAGE_TABLE table, UINT32 pml4_idx)
{
    if (table->PML3[pml4_idx])
        return table->PML3[pml4_idx];

    UINT64 pml3_pa = 0;
    PVOID  pml3    = ept_alloc_table(table, &pml3_pa);
    if (!pml3)
        return NULL;

    table->PML3[pml4_idx] = pml3;
    ((PUINT64)table->PML4_Page)[pml4_idx] = ept_make_nonleaf(pml3_pa);
    return pml3;
}

static PUINT64
ept_ensure_pml2_slot(PVMM_EPT_PAGE_TABLE table, UINT64 addr)
{
    UINT32 pml4_idx = (UINT32)(addr >> 39) & 0x1FFU;
    UINT32 pml3_idx = (UINT32)(addr >> 30) & 0x1FFU;
    UINT32 pml2_idx = (UINT32)(addr >> 21) & 0x1FFU;

    PVOID pml3 = ept_ensure_pml3(table, pml4_idx);
    if (!pml3)
        return NULL;

    PUINT64 pml3e = &((PUINT64)pml3)[pml3_idx];
    if (!ept_entry_is_present(*pml3e))
    {
        UINT64 pml2_pa = 0;
        PVOID  pml2    = ept_alloc_table(table, &pml2_pa);
        if (!pml2)
            return NULL;

        *pml3e = ept_make_nonleaf(pml2_pa);
        return &((PUINT64)pml2)[pml2_idx];
    }

    PVOID pml2 = ept_tracked_pa_to_va(table, ept_entry_next_pa(*pml3e));
    if (!pml2)
        return NULL;

    return &((PUINT64)pml2)[pml2_idx];
}

static BOOLEAN
ept_map_2mb(PVMM_EPT_PAGE_TABLE table, UINT64 addr2mb)
{
    PUINT64 slot = ept_ensure_pml2_slot(table, addr2mb);
    if (!slot)
        return FALSE;

    //
    // already mapped (overlapping low-4GB and RAM ranges) — avoid leaking
    // a duplicate PML1 table if already split
    //
    if (ept_entry_is_present(*slot))
        return TRUE;

    SIZE_T pfn2mb = (SIZE_T)(addr2mb / SIZE_2_MB);

    if (ept_valid_for_large_page(pfn2mb))
    {
        *slot = ept_make_leaf_2mb(pfn2mb, ept_get_memory_type(pfn2mb, TRUE));
        return TRUE;
    }

    //
    // crosses an MTRR or RAM boundary — split into 512 4KB pages
    //
    UINT64 pml1_pa = 0;
    PVOID  pml1    = ept_alloc_table(table, &pml1_pa);
    if (!pml1)
        return FALSE;

    PUINT64 pml1_entries = (PUINT64)pml1;
    for (UINT32 i = 0; i < 512; i++)
    {
        SIZE_T pfn4k = pfn2mb * 512 + i;
        pml1_entries[i] = ept_make_leaf_4kb(pfn4k, ept_get_memory_type(pfn4k, FALSE));
    }

    *slot = ept_make_nonleaf(pml1_pa);
    return TRUE;
}

static BOOLEAN
ept_map_1gb(PVMM_EPT_PAGE_TABLE table, UINT64 addr1gb)
{
    UINT32 pml4_idx = (UINT32)(addr1gb >> 39) & 0x1FFU;
    UINT32 pml3_idx = (UINT32)(addr1gb >> 30) & 0x1FFU;

    PVOID pml3 = ept_ensure_pml3(table, pml4_idx);
    if (!pml3)
        return FALSE;

    PUINT64 pml3e = &((PUINT64)pml3)[pml3_idx];
    if (ept_entry_is_present(*pml3e))
        return TRUE;

    SIZE_T pfn1gb = (SIZE_T)(addr1gb / SIZE_1_GB);
    UINT8  mt     = ept_get_memory_type(pfn1gb * 512, TRUE);
    *pml3e = ept_make_leaf_1gb(pfn1gb, mt);
    return TRUE;
}

static BOOLEAN
ept_map_range(PVMM_EPT_PAGE_TABLE table, UINT64 base, UINT64 end)
{
    if (base >= EPT_MAX_PHYS_SUPPORTED)
        return TRUE;

    if (end >= EPT_MAX_PHYS_SUPPORTED)
    {
        HV_LOG("EPT/NPT: clamping range end 0x%llx to 48-bit walk limit\n", end);
        end = EPT_MAX_PHYS_SUPPORTED - 1ULL;
    }

    UINT64 addr = base & ~(SIZE_2_MB - 1ULL);
    while (addr <= end)
    {
        //
        // use 1GB huge pages whenever supported, aligned, and uniform across
        // MTRR and RAM boundaries (reduces EPT/NPT memory & TLB pressure).
        //
        if (g_ept->huge_1gb_supported &&
            (addr & (SIZE_1_GB - 1ULL)) == 0 &&
            (addr + SIZE_1_GB - 1ULL) <= end &&
            ept_valid_for_1gb_page((SIZE_T)(addr / SIZE_1_GB)))
        {
            UINT32 pml4_idx = (UINT32)(addr >> 39) & 0x1FFU;
            UINT32 pml3_idx = (UINT32)(addr >> 30) & 0x1FFU;
            PVOID  pml3     = table->PML3[pml4_idx];
            BOOLEAN already_split = (pml3 && ept_entry_is_present(((PUINT64)pml3)[pml3_idx]) &&
                                     !ept_entry_is_large(((PUINT64)pml3)[pml3_idx]));

            if (!already_split)
            {
                if (!ept_map_1gb(table, addr))
                    return FALSE;
                if (addr > EPT_MAX_PHYS_SUPPORTED - SIZE_1_GB)
                    break;
                addr += SIZE_1_GB;
                continue;
            }
        }

        if (!ept_map_2mb(table, addr))
            return FALSE;
        if (addr > EPT_MAX_PHYS_SUPPORTED - SIZE_2_MB)
            break;
        addr += SIZE_2_MB;
    }
    return TRUE;
}

static VOID
ept_free_page_table(PVMM_EPT_PAGE_TABLE table)
{
    if (!table)
        return;

    for (UINT32 i = 0; i < table->TrackedCount; i++)
    {
        if (table->Tracked[i].Va)
            hv_free_contiguous(table->Tracked[i].Va);
    }

    for (UINT32 i = 0; i < table->DynPoolCount; i++)
    {
        if (table->DynPool[i].Va)
            hv_free_contiguous(table->DynPool[i].Va);
    }

    if (table->PML4_Page)
        hv_free_contiguous(table->PML4_Page);

    hv_pool_free(table);
}

static PVMM_EPT_PAGE_TABLE
ept_alloc_identity_map(VOID)
{
    PVMM_EPT_PAGE_TABLE table = (PVMM_EPT_PAGE_TABLE)hv_pool_alloc(sizeof(VMM_EPT_PAGE_TABLE));
    if (!table)
        return NULL;
    RtlZeroMemory(table, sizeof(VMM_EPT_PAGE_TABLE));

    //
    // allocate PML4 via hv_alloc_contiguous(PAGE_SIZE) for guaranteed 4KB
    // physical alignment (even under Driver Verifier Special Pool).
    //
    table->PML4_Page = hv_alloc_contiguous(PAGE_SIZE);
    if (!table->PML4_Page)
    {
        hv_pool_free(table);
        return NULL;
    }
    RtlZeroMemory(table->PML4_Page, PAGE_SIZE);
    table->PML4_Pa = va_to_pa(table->PML4_Page);

    //
    // pre-allocate root-mode dynamic page pool (for on-demand above-4G MMIO
    // mapping such as 64-bit PCIe BARs / Resizable BAR).
    //
    for (UINT32 i = 0; i < EPT_DYN_POOL_PAGES; i++)
    {
        PVOID page = hv_alloc_contiguous(PAGE_SIZE);
        if (!page)
            break;
        RtlZeroMemory(page, PAGE_SIZE);
        table->DynPool[table->DynPoolCount].Va = page;
        table->DynPool[table->DynPoolCount].Pa = va_to_pa(page);
        table->DynPoolCount++;
    }

    //
    // low 4GB always (covers chipset MMIO + low RAM)
    //
    if (!ept_map_range(table, 0, 0xFFFFFFFFULL))
    {
        HV_LOG("EPT/NPT: failed to map low 4GB\n");
        ept_free_page_table(table);
        return NULL;
    }

    //
    // all physical RAM ranges (handles >512GB machines)
    //
    for (UINT32 i = 0; i < g_ept->num_ram_ranges; i++)
    {
        if (!ept_map_range(table, g_ept->ram_ranges[i].base, g_ept->ram_ranges[i].end))
        {
            HV_LOG("EPT/NPT: failed to map RAM range 0x%llx-0x%llx\n",
                   g_ept->ram_ranges[i].base, g_ept->ram_ranges[i].end);
            ept_free_page_table(table);
            return NULL;
        }
    }

    HV_LOG("EPT/NPT: identity map built (%u table pages, %u dyn pool pages)\n",
           table->TrackedCount, table->DynPoolCount);
    return table;
}

//
// root-mode-safe dynamic UC mapping for unmapped above-4G MMIO (64-bit PCIe BARs,
// Resizable BAR, APIC/ACPI tables outside RAM map). ZERO Windows API calls!
// returns TRUE if the GPA was newly mapped (or already mapped by a racing core)
// so the guest instruction can be retried; FALSE if out of range / pool exhausted.
//
BOOLEAN
ept_handle_dynamic_mmio(UINT64 gpa)
{
    if (!g_ept || !g_ept->page_table)
        return FALSE;

    if (gpa >= EPT_MAX_PHYS_SUPPORTED)
        return FALSE;

    //
    // reject non-architectural physical addresses beyond MAXPHYADDR
    //
    if (g_ept->maxphyaddr < 48 && gpa >= (1ULL << g_ept->maxphyaddr))
        return FALSE;

    PVMM_EPT_PAGE_TABLE table = g_ept->page_table;
    UINT64 addr2mb  = gpa & ~(SIZE_2_MB - 1ULL);
    UINT32 pml4_idx = (UINT32)(addr2mb >> 39) & 0x1FFU;
    UINT32 pml3_idx = (UINT32)(addr2mb >> 30) & 0x1FFU;
    UINT32 pml2_idx = (UINT32)(addr2mb >> 21) & 0x1FFU;
    BOOLEAN mapped  = FALSE;

    //
    // acquire simple root-mode spinlock
    //
    while (_InterlockedCompareExchange(&table->DynLock, 1, 0) != 0)
        _mm_pause();

    //
    // step 1: ensure PML3
    //
    PVOID pml3 = table->PML3[pml4_idx];
    if (!pml3)
    {
        if (table->DynPoolUsed < table->DynPoolCount)
        {
            VMM_EPT_PAGE *pg = &table->DynPool[table->DynPoolUsed++];
            pml3 = pg->Va;
            table->PML3[pml4_idx] = pml3;
            ((PUINT64)table->PML4_Page)[pml4_idx] = ept_make_nonleaf(pg->Pa);
        }
    }

    if (pml3)
    {
        //
        // step 2: ensure PML2
        //
        PUINT64 pml3e = &((PUINT64)pml3)[pml3_idx];
        PVOID   pml2  = NULL;

        if (!ept_entry_is_present(*pml3e))
        {
            if (table->DynPoolUsed < table->DynPoolCount)
            {
                VMM_EPT_PAGE *pg = &table->DynPool[table->DynPoolUsed++];
                pml2 = pg->Va;
                *pml3e = ept_make_nonleaf(pg->Pa);
            }
        }
        else if (ept_entry_is_large(*pml3e))
        {
            // already mapped by a 1GB huge page
            mapped = TRUE;
        }
        else
        {
            pml2 = ept_tracked_pa_to_va(table, ept_entry_next_pa(*pml3e));
        }

        if (pml2)
        {
            //
            // step 3: map 2MB chunk as UC if currently absent
            //
            PUINT64 pml2e = &((PUINT64)pml2)[pml2_idx];
            if (!ept_entry_is_present(*pml2e))
            {
                SIZE_T pfn2mb = (SIZE_T)(addr2mb / SIZE_2_MB);
                *pml2e = ept_make_leaf_2mb(pfn2mb, MEMORY_TYPE_UNCACHEABLE);
                _InterlockedIncrement64(&table->DynMappedCount);
                mapped = TRUE;
            }
            else
            {
                //
                // another core already mapped this 2MB chunk concurrently
                //
                mapped = TRUE;
            }
        }
    }

    _InterlockedExchange(&table->DynLock, 0);
    return mapped;
}

BOOLEAN
ept_map_into_hostcr3(VOID)
{
    if (!g_ept)
        return TRUE;

    if (!hostcr3_map_range(g_ept, sizeof(EPT_STATE), FALSE))
        return FALSE;

    if (g_ept->page_table)
    {
        PVMM_EPT_PAGE_TABLE table = g_ept->page_table;

        if (!hostcr3_map_range(table, sizeof(VMM_EPT_PAGE_TABLE), FALSE))
            return FALSE;

        if (table->PML4_Page && !hostcr3_map_range(table->PML4_Page, PAGE_SIZE, FALSE))
            return FALSE;

        for (UINT32 i = 0; i < table->TrackedCount; i++)
        {
            if (table->Tracked[i].Va && !hostcr3_map_range(table->Tracked[i].Va, PAGE_SIZE, FALSE))
                return FALSE;
        }

        for (UINT32 i = 0; i < table->DynPoolCount; i++)
        {
            if (table->DynPool[i].Va && !hostcr3_map_range(table->DynPool[i].Va, PAGE_SIZE, FALSE))
                return FALSE;
        }
    }

    return TRUE;
}

BOOLEAN
ept_init(VOID)
{
    g_ept = (EPT_STATE *)hv_pool_alloc(sizeof(EPT_STATE));
    if (!g_ept)
        return FALSE;
    RtlZeroMemory(g_ept, sizeof(EPT_STATE));

    InitializeListHead(&g_ept->hooked_pages);

    g_ept->maxphyaddr = g_cpu.maxphyaddr;

    if (!ept_check_features())
        return FALSE;

    if (!ept_build_mtrr_map())
        return FALSE;

    g_ept->page_table = ept_alloc_identity_map();
    if (!g_ept->page_table)
        return FALSE;

    UINT64 pml4_pa = g_ept->page_table->PML4_Pa;

    for (UINT32 i = 0; i < g_vcpu_capacity; i++)
    {
        EPT_POINTER eptp = {0};
        eptp.MemoryType                = MEMORY_TYPE_WRITE_BACK;
        eptp.EnableAccessAndDirtyFlags = g_ept->ad_supported;
        eptp.PageWalkLength            = 3;   // 4-level walk (value = levels - 1)
        eptp.PageFrameNumber           = pml4_pa / PAGE_SIZE;

        g_vcpu[i].ept_pointer = eptp;         // Intel EPT
        g_vcpu[i].npt_cr3     = pml4_pa;      // AMD NPT
    }

    HV_LOG("EPT/NPT initialized (shared %s table) for %u processors\n",
           g_ept->is_npt ? "NPT" : "EPT", g_cpu_count);
    return TRUE;
}

UINT64
ept_pml4_pa(VOID)
{
    if (!g_ept || !g_ept->page_table)
        return 0;
    return g_ept->page_table->PML4_Pa;
}

VOID
ept_destroy(VOID)
{
    if (!g_ept)
        return;

    if (g_ept->page_table)
    {
        ept_free_page_table(g_ept->page_table);
        g_ept->page_table = NULL;
    }

    hv_pool_free(g_ept);
    g_ept = NULL;
}

BOOLEAN
ept_split_large_page(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr)
{
    PEPT_PML2_ENTRY target = ept_get_pml2(page_table, phys_addr);
    if (!target || !ept_entry_is_large(target->AsUInt))
        return FALSE;

    UINT64 pml1_pa = 0;
    PVOID  pml1    = ept_alloc_table(page_table, &pml1_pa);
    if (!pml1)
        return FALSE;

    SIZE_T  pfn2mb       = (SIZE_T)((phys_addr & ~(SIZE_2_MB - 1ULL)) / SIZE_2_MB);
    PUINT64 pml1_entries = (PUINT64)pml1;

    for (UINT32 i = 0; i < 512; i++)
    {
        SIZE_T pfn4k = pfn2mb * 512 + i;
        pml1_entries[i] = ept_make_leaf_4kb(pfn4k, ept_get_memory_type(pfn4k, FALSE));
    }

    *(PUINT64)target = ept_make_nonleaf(pml1_pa);
    return TRUE;
}

PEPT_PML2_ENTRY
ept_get_pml2(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr)
{
    SIZE_T pml4_idx = ADDRMASK_EPT_PML4_INDEX(phys_addr);
    SIZE_T pml3_idx = ADDRMASK_EPT_PML3_INDEX(phys_addr);
    SIZE_T pml2_idx = ADDRMASK_EPT_PML2_INDEX(phys_addr);

    PVOID pml3 = page_table->PML3[pml4_idx];
    if (!pml3)
        return NULL;

    UINT64 pml3e = ((PUINT64)pml3)[pml3_idx];
    if (!ept_entry_is_present(pml3e) || ept_entry_is_large(pml3e))
        return NULL;

    PVOID pml2 = ept_tracked_pa_to_va(page_table, ept_entry_next_pa(pml3e));
    if (!pml2)
        return NULL;

    return (PEPT_PML2_ENTRY)&((PUINT64)pml2)[pml2_idx];
}

PEPT_PML1_ENTRY
ept_get_pml1(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr)
{
    PEPT_PML2_ENTRY pml2 = ept_get_pml2(page_table, phys_addr);
    if (!pml2 || !ept_entry_is_present(pml2->AsUInt) || ept_entry_is_large(pml2->AsUInt))
        return NULL;

    PVOID pml1 = ept_tracked_pa_to_va(page_table, ept_entry_next_pa(pml2->AsUInt));
    if (!pml1)
        return NULL;

    return &((PEPT_PML1_ENTRY)pml1)[ADDRMASK_EPT_PML1_INDEX(phys_addr)];
}

static VOID
ept_broadcast_flush_cb(ULONG cpu_index, PVOID context)
{
    UNREFERENCED_PARAMETER(context);
    if (g_vcpu && cpu_index < g_vcpu_capacity && g_vcpu[cpu_index].launched)
    {
        if (g_hv_backend == &g_vmx_backend)
            asm_vmx_vmcall(VMCALL_INVEPT, 0, 0, 0);
        else if (g_hv_backend == &g_svm_backend)
            asm_svm_vmcall(VMCALL_INVEPT, 0, 0, 0);
    }
}

static PUINT64
ept_ensure_4kb_pte_from_dynpool(PVMM_EPT_PAGE_TABLE table, UINT64 phys_addr)
{
    UINT64 page_addr = phys_addr & ~0xFFFULL;
    UINT32 pml4_idx  = (UINT32)(page_addr >> 39) & 0x1FFU;
    UINT32 pml3_idx  = (UINT32)(page_addr >> 30) & 0x1FFU;
    UINT32 pml2_idx  = (UINT32)(page_addr >> 21) & 0x1FFU;
    UINT32 pml1_idx  = (UINT32)(page_addr >> 12) & 0x1FFU;
    PUINT64 result   = NULL;

    while (_InterlockedCompareExchange(&table->DynLock, 1, 0) != 0)
        _mm_pause();

    PVOID pml3 = table->PML3[pml4_idx];
    if (!pml3)
        goto unlock;

    PUINT64 pml3e = &((PUINT64)pml3)[pml3_idx];
    if (!ept_entry_is_present(*pml3e))
        goto unlock;

    //
    // if 1GB huge page, split into 512 2MB pages using a pre-mapped DynPool page
    //
    if (ept_entry_is_large(*pml3e))
    {
        if (table->DynPoolUsed >= table->DynPoolCount)
            goto unlock;

        VMM_EPT_PAGE *pg   = &table->DynPool[table->DynPoolUsed++];
        PUINT64       pml2 = (PUINT64)pg->Va;
        SIZE_T        base2mb = (SIZE_T)((page_addr & ~(SIZE_1_GB - 1ULL)) / SIZE_2_MB);

        for (UINT32 i = 0; i < 512; i++)
            pml2[i] = ept_make_leaf_2mb(base2mb + i, ept_get_memory_type(base2mb + i, TRUE));

        *pml3e = ept_make_nonleaf(pg->Pa);
    }

    PUINT64 pml2 = (PUINT64)ept_tracked_pa_to_va(table, ept_entry_next_pa(*pml3e));
    if (!pml2)
        goto unlock;

    PUINT64 pml2e = &pml2[pml2_idx];
    if (!ept_entry_is_present(*pml2e))
        goto unlock;

    //
    // if 2MB large page, split into 512 4KB pages using a pre-mapped DynPool page
    //
    if (ept_entry_is_large(*pml2e))
    {
        if (table->DynPoolUsed >= table->DynPoolCount)
            goto unlock;

        VMM_EPT_PAGE *pg   = &table->DynPool[table->DynPoolUsed++];
        PUINT64       pml1 = (PUINT64)pg->Va;
        SIZE_T        base4k = (SIZE_T)((page_addr & ~(SIZE_2_MB - 1ULL)) / PAGE_SIZE);

        for (UINT32 i = 0; i < 512; i++)
            pml1[i] = ept_make_leaf_4kb(base4k + i, ept_get_memory_type(base4k + i, FALSE));

        *pml2e = ept_make_nonleaf(pg->Pa);
    }

    PUINT64 pml1 = (PUINT64)ept_tracked_pa_to_va(table, ept_entry_next_pa(*pml2e));
    if (pml1)
        result = &pml1[pml1_idx];

unlock:
    _InterlockedExchange(&table->DynLock, 0);
    return result;
}

BOOLEAN
ept_add_watchpoint(UINT64 phys_addr, UINT32 flags)
{
    if (!g_ept || !g_ept->page_table || flags == 0)
        return FALSE;

    UINT64  page = phys_addr & ~0xFFFULL;
    PUINT64 pte  = ept_ensure_4kb_pte_from_dynpool(g_ept->page_table, page);
    if (!pte)
        return FALSE;

    //
    // compute restricted trap entry:
    // Intel EPT: clear Read(bit 0), Write(bit 1), Execute(bit 2) as requested.
    //            (note: Intel EPT forbids Write-only without Read, so trapping Read
    //             must also clear Write to avoid EPT Misconfiguration!)
    // AMD NPT:   Present(bit 0) clears R+W+X, Write(bit 1) traps writes, NX(bit 63) traps exec.
    //
    while (_InterlockedCompareExchange(&g_ept->wp_lock, 1, 0) != 0)
        _mm_pause();

    INT32 slot = -1;
    for (UINT32 i = 0; i < HV_MAX_WATCHPOINTS; i++)
    {
        if (g_ept->watchpoints[i].active && g_ept->watchpoints[i].phys_page == page)
        {
            slot = (INT32)i;
            break;
        }
        if (!g_ept->watchpoints[i].active && slot < 0)
            slot = (INT32)i;
    }

    if (slot < 0)
    {
        _InterlockedExchange(&g_ept->wp_lock, 0);
        return FALSE;
    }

    EPT_WATCHPOINT *wp = &g_ept->watchpoints[slot];
    UINT64 orig = wp->active ? wp->orig_entry : *pte;
    UINT64 trap = orig;

    if (g_ept->is_npt)
    {
        if (flags & HV_WP_TRAP_READ)
            trap &= ~NPT_PTE_PRESENT;
        if (flags & HV_WP_TRAP_WRITE)
            trap &= ~NPT_PTE_WRITE;
        if (flags & HV_WP_TRAP_EXEC)
            trap |= (1ULL << 63); // NX bit
    }
    else
    {
        if (flags & HV_WP_TRAP_READ)
            trap &= ~3ULL;        // clear R & W (avoid write-only EPT misconfig!)
        if (flags & HV_WP_TRAP_WRITE)
            trap &= ~2ULL;        // clear W
        if (flags & HV_WP_TRAP_EXEC)
            trap &= ~4ULL;        // clear X
    }

    if (!wp->active)
        g_ept->active_watchpoints++;

    wp->active     = TRUE;
    wp->flags      = flags;
    wp->phys_page  = page;
    wp->orig_entry = orig;
    wp->trap_entry = trap;
    wp->pte_va     = pte;
    wp->hit_count  = 0;

    *pte = trap;

    _InterlockedExchange(&g_ept->wp_lock, 0);

    if (g_hv_active)
        hv_for_each_cpu(ept_broadcast_flush_cb, NULL);

    return TRUE;
}

BOOLEAN
ept_remove_watchpoint(UINT64 phys_addr)
{
    if (!g_ept)
        return FALSE;

    UINT64  page  = phys_addr & ~0xFFFULL;
    BOOLEAN found = FALSE;

    while (_InterlockedCompareExchange(&g_ept->wp_lock, 1, 0) != 0)
        _mm_pause();

    for (UINT32 i = 0; i < HV_MAX_WATCHPOINTS; i++)
    {
        EPT_WATCHPOINT *wp = &g_ept->watchpoints[i];
        if (wp->active && wp->phys_page == page)
        {
            if (wp->pte_va)
                *wp->pte_va = wp->orig_entry;
            wp->active = FALSE;
            wp->pte_va = NULL;
            if (g_ept->active_watchpoints > 0)
                g_ept->active_watchpoints--;
            found = TRUE;
            break;
        }
    }

    _InterlockedExchange(&g_ept->wp_lock, 0);

    if (found && g_hv_active)
        hv_for_each_cpu(ept_broadcast_flush_cb, NULL);

    return found;
}

//
// root-mode watchpoint lookup (ZERO Windows API calls)
//
INT32
ept_find_watchpoint_root(UINT64 gpa)
{
    if (!g_ept || g_ept->active_watchpoints == 0)
        return -1;

    UINT64 page = gpa & ~0xFFFULL;
    for (UINT32 i = 0; i < HV_MAX_WATCHPOINTS; i++)
    {
        if (g_ept->watchpoints[i].active && g_ept->watchpoints[i].phys_page == page)
            return (INT32)i;
    }
    return -1;
}

VOID
ept_watchpoint_disarm_root(UINT32 idx)
{
    if (!g_ept || idx >= HV_MAX_WATCHPOINTS)
        return;

    EPT_WATCHPOINT *wp = &g_ept->watchpoints[idx];
    if (wp->active && wp->pte_va)
    {
        *wp->pte_va = wp->orig_entry;
        _InterlockedIncrement64(&wp->hit_count);
    }
}

VOID
ept_watchpoint_rearm_root(UINT32 idx)
{
    if (!g_ept || idx >= HV_MAX_WATCHPOINTS)
        return;

    EPT_WATCHPOINT *wp = &g_ept->watchpoints[idx];
    if (wp->active && wp->pte_va)
        *wp->pte_va = wp->trap_entry;
}

VOID
ept_invept_single(EPT_POINTER ept_ptr)
{
    INVEPT_DESCRIPTOR desc = {0};
    desc.EptPointer = ept_ptr;
    asm_invept(InveptSingleContext, &desc);
}

VOID
ept_invept_all(VOID)
{
    INVEPT_DESCRIPTOR desc = {0};
    asm_invept(InveptAllContexts, &desc);
}

VOID
vpid_invvpid_single(UINT16 vpid)
{
    INVVPID_DESCRIPTOR desc = {0};
    desc.Vpid = vpid;
    asm_invvpid(InvvpidSingleContext, &desc);
}
