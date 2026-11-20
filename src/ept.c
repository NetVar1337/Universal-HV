/*
*   ept.c - extended page tables (Intel EPT) / nested paging (AMD NPT)
*
*   builds a shared identity-mapped page table (guest physical == host
*   physical) covering:
*     - the low 4GB always (RAM + MMIO holes below 4GB)
*     - every RAM range reported by MmGetPhysicalMemoryRanges
*
*   this makes the map correct on machines with more than 512GB of RAM and
*   on LA57 (5-level paging) systems: the table is allocated dynamically
*   per 512GB/1GB/2MB chunk instead of assuming a fixed 512GB layout, and it
*   is clamped to 48-bit physical addresses (4-level walk, 256TB — beyond
*   any shipping machine).
*
*   the same page-table format is used for AMD NPT (nested_cr3 points at the
*   PML4), so one builder serves both backends.
*/
#include "hv.h"

#define EPT_MAX_PHYS_SUPPORTED   (1ULL << 48)   // 4-level walk limit

BOOLEAN
ept_check_features(VOID)
{
    IA32_MTRR_DEF_TYPE_REGISTER mtrr_def;

    mtrr_def.AsUInt = __readmsr(IA32_MTRR_DEF_TYPE);

    if (g_cpu.vendor == HV_VENDOR_INTEL)
    {
        IA32_VMX_EPT_VPID_CAP_REGISTER vpid_reg;

        vpid_reg.AsUInt = __readmsr(IA32_VMX_EPT_VPID_CAP);

        if (!vpid_reg.PageWalkLength4 || !vpid_reg.MemoryTypeWriteBack || !vpid_reg.Pde2MbPages)
        {
            DbgPrintEx(0, 0, "[hv] EPT: missing required features (PW4=%d WB=%d 2MB=%d)\n",
                     vpid_reg.PageWalkLength4, vpid_reg.MemoryTypeWriteBack, vpid_reg.Pde2MbPages);
            return FALSE;
        }

        g_ept->ad_supported = vpid_reg.EptAccessedAndDirtyFlags ? TRUE : FALSE;

        g_ept->invvpid_supported              = vpid_reg.Invvpid ? TRUE : FALSE;
        g_ept->invvpid_individual_addr        = vpid_reg.InvvpidIndividualAddress ? TRUE : FALSE;
        g_ept->invvpid_single_context         = vpid_reg.InvvpidSingleContext ? TRUE : FALSE;
        g_ept->invvpid_all_contexts           = vpid_reg.InvvpidAllContexts ? TRUE : FALSE;
        g_ept->invvpid_single_retaining_globals = vpid_reg.InvvpidSingleContextRetainingGlobals ? TRUE : FALSE;

        //
        // EPT requires the secondary "activate secondary controls" and
        // "enable EPT" bits to be allowed-1. without them there is no EPT
        // and this hypervisor cannot run (no shadow paging fallback).
        //
        {
            IA32_VMX_BASIC_REGISTER vmx_basic = {0};
            MSR msr = {0};
            vmx_basic.AsUInt = __readmsr(IA32_VMX_BASIC);
            msr.Flags = __readmsr(vmx_basic.VmxControls ? IA32_VMX_TRUE_PROCBASED_CTLS
                                                        : IA32_VMX_PROCBASED_CTLS);
            if (!(msr.Fields.High & CPU_BASED_VM_EXEC_CTRL_ACTIVATE_SECONDARY_CONTROLS))
            {
                DbgPrintEx(0, 0, "[hv] EPT: secondary controls not supported — CPU too old\n");
                return FALSE;
            }
            msr.Flags = __readmsr(IA32_VMX_PROCBASED_CTLS2);
            if (!(msr.Fields.High & CPU_BASED_VM_EXEC_CTRL2_ENABLE_EPT))
            {
                DbgPrintEx(0, 0, "[hv] EPT: ENABLE_EPT not supported on this CPU\n");
                return FALSE;
            }
        }

        DbgPrintEx(0, 0, "[hv] INVVPID caps: supported=%d individual=%d single=%d all=%d retaining=%d\n",
                 g_ept->invvpid_supported,
                 g_ept->invvpid_individual_addr,
                 g_ept->invvpid_single_context,
                 g_ept->invvpid_all_contexts,
                 g_ept->invvpid_single_retaining_globals);
    }
    else if (g_cpu.vendor == HV_VENDOR_AMD)
    {
        g_ept->npt_supported = (g_cpu.svm_features & SVM_FEATURE_NP) ? TRUE : FALSE;
        if (!g_ept->npt_supported)
        {
            DbgPrintEx(0, 0, "[hv] NPT: nested paging not supported on this CPU\n");
            return FALSE;
        }
    }

    if (!mtrr_def.MtrrEnable)
    {
        //
        // legal on some firmware configurations; everything defaults to UC
        // except what the RAM map says (WB).
        //
        DbgPrintEx(0, 0, "[hv] EPT/NPT: MTRR not enabled, defaulting to UC\n");
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
    SIZE_T page_addr = is_large_page ? pfn * SIZE_2_MB : pfn * PAGE_SIZE;
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
                page_addr >= range->phys_base && page_addr < range->phys_end)
                return range->mem_type;
        }
        return MEMORY_TYPE_UNCACHEABLE;
    }

    for (UINT32 i = 0; i < g_ept->num_ranges; i++)
    {
        MTRR_RANGE_DESCRIPTOR * range = &g_ept->mem_ranges[i];

        if (page_addr >= range->phys_base &&
            page_addr < range->phys_end)
        {
            if (range->fixed)
            {
                target_type = range->mem_type;
                break;
            }

            if (target_type == MEMORY_TYPE_UNCACHEABLE)
            {
                target_type = range->mem_type;
                break;
            }

            if (target_type == MEMORY_TYPE_WRITE_THROUGH ||
                range->mem_type == MEMORY_TYPE_WRITE_THROUGH)
            {
                if (target_type == MEMORY_TYPE_WRITE_BACK)
                {
                    target_type = MEMORY_TYPE_WRITE_THROUGH;
                    continue;
                }
            }

            target_type = range->mem_type;
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
            desc->phys_base = 0x10000 * i;
            desc->phys_end  = 0x10000 * i + 0x10000 - 1;
            desc->fixed     = TRUE;
        }

        for (UINT32 i = 0; i < 2 && g_ept->num_ranges < MAX_MTRR_RANGES; i++)
        {
            IA32_MTRR_FIXED_RANGE_TYPE k16_types = { __readmsr(IA32_MTRR_FIX16K_80000 + i) };
            for (UINT32 j = 0; j < 8 && g_ept->num_ranges < MAX_MTRR_RANGES; j++)
            {
                desc = &g_ept->mem_ranges[g_ept->num_ranges++];
                desc->mem_type  = k16_types.s.Types[j];
                desc->phys_base = 0x80000 + (i * 0x20000) + (j * 0x4000);
                desc->phys_end  = desc->phys_base + 0x4000 - 1;
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
                desc->phys_base = 0xC0000 + (i * 0x8000) + (j * 0x1000);
                desc->phys_end  = desc->phys_base + 0x1000 - 1;
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
            desc = &g_ept->mem_ranges[g_ept->num_ranges++];
            desc->phys_base = cur_base.PageFrameNumber * PAGE_SIZE;

            ULONG mask_bits;
            _BitScanForward64(&mask_bits, cur_mask.PageFrameNumber * PAGE_SIZE);

            desc->phys_end = desc->phys_base + ((1ULL << mask_bits) - 1ULL);
            desc->mem_type = (UINT8)cur_base.Type;
            desc->fixed    = FALSE;
        }
    }

    //
    // physical RAM ranges (drives the identity map on big machines)
    //
    {
        PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
        if (ranges)
        {
            for (UINT32 i = 0; ranges[i].BaseAddress.QuadPart != 0 || ranges[i].NumberOfBytes.QuadPart != 0; i++)
            {
                if (g_ept->num_ram_ranges >= MAX_RAM_RANGES)
                    break;
                g_ept->ram_ranges[g_ept->num_ram_ranges].base = (UINT64)ranges[i].BaseAddress.QuadPart;
                g_ept->ram_ranges[g_ept->num_ram_ranges].end  =
                    (UINT64)ranges[i].BaseAddress.QuadPart + (UINT64)ranges[i].NumberOfBytes.QuadPart - 1;
                g_ept->num_ram_ranges++;
            }
            ExFreePool(ranges);
        }
    }

    DbgPrintEx(0, 0, "[hv] EPT/NPT: %u MTRR ranges, %u RAM ranges, maxphyaddr=%u\n",
             g_ept->num_ranges, g_ept->num_ram_ranges, g_ept->maxphyaddr);

    return TRUE;
}

BOOLEAN
ept_valid_for_large_page(SIZE_T pfn2mb)
{
    SIZE_T start_addr = pfn2mb * SIZE_2_MB;
    SIZE_T end_addr   = start_addr + SIZE_2_MB - 1;

    //
    // must not cross an MTRR boundary
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
    // must not cross a RAM/non-RAM boundary (MMIO hole inside the 2MB chunk)
    //
    if (ept_addr_in_ram(start_addr) != ept_addr_in_ram(end_addr))
        return FALSE;

    return TRUE;
}

static PVOID
ept_alloc_table(PVMM_EPT_PAGE_TABLE table)
{
    PVOID page = hv_alloc_contiguous(PAGE_SIZE);
    if (!page)
        return NULL;

    RtlZeroMemory(page, PAGE_SIZE);

    PVMM_EPT_ALLOC alloc = (PVMM_EPT_ALLOC)hv_pool_alloc(sizeof(VMM_EPT_ALLOC));
    if (!alloc)
    {
        hv_free_contiguous(page);
        return NULL;
    }
    alloc->Page = page;
    InsertTailList(&table->AllocList, &alloc->Link);
    table->AllocCount++;
    return page;
}

/*
*   ensure the PML3 table for pml4 index exists; returns its VA
*/
static PVOID
ept_ensure_pml3(PVMM_EPT_PAGE_TABLE table, UINT32 pml4_idx)
{
    if (table->PML3[pml4_idx])
        return table->PML3[pml4_idx];

    PVOID pml3 = ept_alloc_table(table);
    if (!pml3)
        return NULL;

    table->PML3[pml4_idx] = pml3;

    EPT_PML4_ENTRY e = {0};
    e.ReadAccess = e.WriteAccess = e.ExecuteAccess = 1;
    e.PageFrameNumber = va_to_pa(pml3) / PAGE_SIZE;
    table->PML4[pml4_idx] = e;

    return pml3;
}

/*
*   ensure the PML2 table (1GB chunk) for a guest-physical address exists;
*   returns pointer to the PML2 entry slot.
*/
static PEPT_PML2_ENTRY
ept_ensure_pml2_entry(PVMM_EPT_PAGE_TABLE table, UINT64 addr)
{
    UINT32 pml4_idx = (UINT32)(addr >> 39) & 0x1FF;
    UINT32 pml3_idx = (UINT32)(addr >> 30) & 0x1FF;
    UINT32 pml2_idx = (UINT32)(addr >> 21) & 0x1FF;

    PVOID pml3 = ept_ensure_pml3(table, pml4_idx);
    if (!pml3)
        return NULL;

    EPT_PML3_POINTER * pml3e = (EPT_PML3_POINTER *)((PUINT8)pml3 + pml3_idx * 8);
    if (!pml3e->ReadAccess)
    {
        PVOID pml2 = ept_alloc_table(table);
        if (!pml2)
            return NULL;

        EPT_PML3_POINTER e = {0};
        e.ReadAccess = e.WriteAccess = e.ExecuteAccess = 1;
        e.PageFrameNumber = va_to_pa(pml2) / PAGE_SIZE;
        *pml3e = e;

        return (PEPT_PML2_ENTRY)((PUINT8)pml2 + pml2_idx * 8);
    }

    PVOID pml2 = pa_to_va(pml3e->PageFrameNumber * PAGE_SIZE);
    return (PEPT_PML2_ENTRY)((PUINT8)pml2 + pml2_idx * 8);
}

/*
*   map one 2MB chunk. splits to 4KB pages when it crosses an MTRR or
*   RAM boundary.
*/
static BOOLEAN
ept_map_2mb(PVMM_EPT_PAGE_TABLE table, UINT64 addr2mb)
{
    PEPT_PML2_ENTRY entry = ept_ensure_pml2_entry(table, addr2mb);
    if (!entry)
        return FALSE;

    SIZE_T pfn2mb = addr2mb / SIZE_2_MB;

    if (ept_valid_for_large_page(pfn2mb))
    {
        EPT_PML2_ENTRY e = {0};
        e.ReadAccess = e.WriteAccess = e.ExecuteAccess = 1;
        e.LargePage  = 1;
        e.MemoryType = ept_get_memory_type(pfn2mb, TRUE);
        e.PageFrameNumber = (UINT32)pfn2mb;
        *entry = e;
        return TRUE;
    }

    //
    // crosses a boundary — split into 512 4KB pages
    //
    PVOID pml1 = ept_alloc_table(table);
    if (!pml1)
        return FALSE;

    for (UINT32 i = 0; i < 512; i++)
    {
        EPT_PML1_ENTRY e = {0};
        e.ReadAccess = e.WriteAccess = e.ExecuteAccess = 1;
        e.MemoryType = ept_get_memory_type(pfn2mb * 512 + i, FALSE);
        e.PageFrameNumber = pfn2mb * 512 + i;
        ((PEPT_PML1_ENTRY)pml1)[i] = e;
    }

    EPT_PML2_POINTER p = {0};
    p.ReadAccess = p.WriteAccess = p.ExecuteAccess = 1;
    p.PageFrameNumber = va_to_pa(pml1) / PAGE_SIZE;
    *(EPT_PML2_POINTER *)entry = p;

    return TRUE;
}

static BOOLEAN
ept_map_range(PVMM_EPT_PAGE_TABLE table, UINT64 base, UINT64 end)
{
    if (end >= EPT_MAX_PHYS_SUPPORTED)
    {
        DbgPrintEx(0, 0, "[hv] EPT/NPT: RAM above 48-bit physical (0x%llx) not mapped (no 4-level walk)\n", end);
        end = EPT_MAX_PHYS_SUPPORTED - 1;
    }

    UINT64 addr = base & ~(SIZE_2_MB - 1);
    for (; addr <= end; addr += SIZE_2_MB)
    {
        if (!ept_map_2mb(table, addr))
            return FALSE;
    }
    return TRUE;
}

/*
*   build the shared identity map: low 4GB (MMIO + low RAM) plus every RAM
*   range in the machine.
*/
static PVMM_EPT_PAGE_TABLE
ept_alloc_identity_map(VOID)
{
    PVMM_EPT_PAGE_TABLE table = (PVMM_EPT_PAGE_TABLE)hv_pool_alloc(sizeof(VMM_EPT_PAGE_TABLE));
    if (!table)
        return NULL;
    RtlZeroMemory(table, sizeof(VMM_EPT_PAGE_TABLE));
    InitializeListHead(&table->AllocList);

    //
    // low 4GB always (covers all chipset MMIO below 4GB)
    //
    if (!ept_map_range(table, 0, 0xFFFFFFFFULL))
    {
        DbgPrintEx(0, 0, "[hv] EPT/NPT: failed to map low 4GB\n");
        return NULL;
    }

    //
    // all RAM ranges (handles >512GB machines)
    //
    for (UINT32 i = 0; i < g_ept->num_ram_ranges; i++)
    {
        if (!ept_map_range(table, g_ept->ram_ranges[i].base, g_ept->ram_ranges[i].end))
        {
            DbgPrintEx(0, 0, "[hv] EPT/NPT: failed to map RAM range 0x%llx-0x%llx\n",
                     g_ept->ram_ranges[i].base, g_ept->ram_ranges[i].end);
            return NULL;
        }
    }

    DbgPrintEx(0, 0, "[hv] EPT/NPT: identity map built (%u table pages)\n", table->AllocCount);
    return table;
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

    //
    // one shared page table for all vCPUs (identity map is identical);
    // per-vCPU pointers are assigned below.
    //
    g_ept->page_table = ept_alloc_identity_map();
    if (!g_ept->page_table)
        return FALSE;

    UINT64 pml4_pa = va_to_pa(&g_ept->page_table->PML4[0]);

    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        EPT_POINTER eptp = {0};
        eptp.MemoryType               = MEMORY_TYPE_WRITE_BACK;
        eptp.EnableAccessAndDirtyFlags = g_ept->ad_supported;
        eptp.PageWalkLength           = 3;   // 4-level walk (value = levels - 1)
        eptp.PageFrameNumber          = pml4_pa / PAGE_SIZE;

        g_vcpu[i].ept_pointer = eptp;         // Intel EPT
        g_vcpu[i].npt_cr3     = pml4_pa;      // AMD NPT
    }

    DbgPrintEx(0, 0, "[hv] EPT/NPT initialized (shared table) for %u processors\n", g_cpu_count);
    return TRUE;
}

UINT64
ept_pml4_pa(VOID)
{
    if (!g_ept || !g_ept->page_table)
        return 0;
    return va_to_pa(&g_ept->page_table->PML4[0]);
}

VOID
ept_destroy(VOID)
{
    if (!g_ept)
        return;

    if (g_ept->page_table)
    {
        PVMM_EPT_PAGE_TABLE table = g_ept->page_table;

        while (!IsListEmpty(&table->AllocList))
        {
            PLIST_ENTRY link = RemoveHeadList(&table->AllocList);
            PVMM_EPT_ALLOC alloc = CONTAINING_RECORD(link, VMM_EPT_ALLOC, Link);
            hv_free_contiguous(alloc->Page);
            hv_pool_free(alloc);
        }

        hv_pool_free(table);
        g_ept->page_table = NULL;
    }

    hv_pool_free(g_ept);
    g_ept = NULL;
}

BOOLEAN
ept_split_large_page(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr)
{
    PEPT_PML2_ENTRY target = ept_get_pml2(page_table, phys_addr);
    if (!target || !target->LargePage)
        return FALSE;

    PVOID pml1 = ept_alloc_table(page_table);
    if (!pml1)
        return FALSE;

    SIZE_T pfn2mb = target->PageFrameNumber;
    for (UINT32 i = 0; i < 512; i++)
    {
        EPT_PML1_ENTRY e = {0};
        e.ReadAccess = e.WriteAccess = e.ExecuteAccess = 1;
        e.MemoryType = ept_get_memory_type(pfn2mb * 512 + i, FALSE);
        e.PageFrameNumber = pfn2mb * 512 + i;
        ((PEPT_PML1_ENTRY)pml1)[i] = e;
    }

    EPT_PML2_POINTER p = {0};
    p.ReadAccess = p.WriteAccess = p.ExecuteAccess = 1;
    p.PageFrameNumber = va_to_pa(pml1) / PAGE_SIZE;
    *(EPT_PML2_POINTER *)target = p;

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

    EPT_PML3_POINTER * pml3e = (EPT_PML3_POINTER *)((PUINT8)pml3 + pml3_idx * 8);
    if (!pml3e->ReadAccess)
        return NULL;

    PVOID pml2 = pa_to_va(pml3e->PageFrameNumber * PAGE_SIZE);
    return (PEPT_PML2_ENTRY)((PUINT8)pml2 + pml2_idx * 8);
}

PEPT_PML1_ENTRY
ept_get_pml1(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr)
{
    PEPT_PML2_ENTRY pml2 = ept_get_pml2(page_table, phys_addr);
    if (!pml2 || pml2->LargePage)
        return NULL;

    PVOID pml1 = pa_to_va(((EPT_PML2_POINTER *)pml2)->PageFrameNumber * PAGE_SIZE);
    if (!pml1)
        return NULL;

    return &((PEPT_PML1_ENTRY)pml1)[ADDRMASK_EPT_PML1_INDEX(phys_addr)];
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
