/*
*   hostcr3.c - minimal, race-free private host page tables (4-level & LA57)
*
*   instead of walking and deep-copying live Windows kernel page tables
*   (which races with the memory manager, consumes up to 64MB, and breaks on
*   LA57 5-level paging), this module builds a dedicated minimal host page
*   table mapping ONLY the exact virtual ranges accessed in VMX-root / SVM
*   host mode:
*     - the Ophion driver image (code + data + g_host_idt + globals)
*     - g_vcpu array
*     - g_ept, VMM_EPT_PAGE_TABLE, and all EPT/NPT + DynPool pages
*     - per-vCPU VMM stacks, private host GDTs, VMCBs, HSAVEs, bitmaps
*
*   all page-table pages are allocated via hv_alloc_contiguous(PAGE_SIZE)
*   so they are strictly 4KB physically aligned even under Driver Verifier.
*/
#include "hv.h"

#define HOST_PTE_PRESENT    (1ULL << 0)
#define HOST_PTE_WRITE      (1ULL << 1)
#define HOST_PTE_NX         (1ULL << 63)
#define HOST_PTE_PFN_MASK   0x000FFFFFFFFFF000ULL

#define MAX_HOST_PT_PAGES   1024

typedef struct _HOST_PT_PAGE {
    PUINT64 Va;
    UINT64  Pa;
} HOST_PT_PAGE;

static HOST_PT_PAGE g_host_pt_pages[MAX_HOST_PT_PAGES];
static UINT32       g_host_pt_count  = 0;
static PUINT64      g_host_root_va   = NULL;
static UINT64       g_host_root_pa   = 0;
static BOOLEAN      g_host_la57      = FALSE;

static PUINT64
host_alloc_table(UINT64 *pa_out)
{
    if (g_host_pt_count >= MAX_HOST_PT_PAGES)
        return NULL;

    PVOID page = hv_alloc_contiguous(PAGE_SIZE);
    if (!page)
        return NULL;

    RtlZeroMemory(page, PAGE_SIZE);
    UINT64 pa = va_to_pa(page);

    g_host_pt_pages[g_host_pt_count].Va = (PUINT64)page;
    g_host_pt_pages[g_host_pt_count].Pa = pa;
    g_host_pt_count++;

    if (pa_out)
        *pa_out = pa;
    return (PUINT64)page;
}

static PUINT64
host_find_table_va(UINT64 pa)
{
    UINT64 target = pa & HOST_PTE_PFN_MASK;
    for (UINT32 i = 0; i < g_host_pt_count; i++)
    {
        if (g_host_pt_pages[i].Pa == target)
            return g_host_pt_pages[i].Va;
    }
    return NULL;
}

static PUINT64
host_ensure_child(PUINT64 table, UINT32 index)
{
    if (table[index] & HOST_PTE_PRESENT)
        return host_find_table_va(table[index]);

    UINT64  child_pa = 0;
    PUINT64 child_va = host_alloc_table(&child_pa);
    if (!child_va)
        return NULL;

    table[index] = HOST_PTE_PRESENT | HOST_PTE_WRITE | (child_pa & HOST_PTE_PFN_MASK);
    return child_va;
}

static BOOLEAN
hostcr3_map_page(UINT64 va, UINT64 pa, BOOLEAN executable)
{
    PUINT64 pml4 = g_host_root_va;

    if (g_host_la57)
    {
        UINT32 pml5_idx = (UINT32)((va >> 48) & 0x1FFU);
        pml4 = host_ensure_child(g_host_root_va, pml5_idx);
        if (!pml4)
            return FALSE;
    }

    UINT32 pml4_idx = (UINT32)((va >> 39) & 0x1FFU);
    UINT32 pdpt_idx = (UINT32)((va >> 30) & 0x1FFU);
    UINT32 pd_idx   = (UINT32)((va >> 21) & 0x1FFU);
    UINT32 pt_idx   = (UINT32)((va >> 12) & 0x1FFU);

    PUINT64 pdpt = host_ensure_child(pml4, pml4_idx);
    if (!pdpt)
        return FALSE;

    PUINT64 pd = host_ensure_child(pdpt, pdpt_idx);
    if (!pd)
        return FALSE;

    PUINT64 pt = host_ensure_child(pd, pd_idx);
    if (!pt)
        return FALSE;

    UINT64 flags = HOST_PTE_PRESENT | HOST_PTE_WRITE;
    if (!executable)
        flags |= HOST_PTE_NX;

    //
    // if a page is mapped twice (e.g. adjacent allocations sharing a 4KB page),
    // preserve executable permission if either mapping requires it.
    //
    if ((pt[pt_idx] & HOST_PTE_PRESENT) && !(pt[pt_idx] & HOST_PTE_NX))
        flags &= ~HOST_PTE_NX;

    pt[pt_idx] = flags | (pa & HOST_PTE_PFN_MASK);
    return TRUE;
}

BOOLEAN
hostcr3_init(VOID)
{
    hostcr3_destroy();

    g_host_la57 = (__readcr4() & CR4_LA57_FLAG) ? TRUE : FALSE;

    g_host_root_va = host_alloc_table(&g_host_root_pa);
    if (!g_host_root_va)
        return FALSE;

    return TRUE;
}

BOOLEAN
hostcr3_map_range(PVOID va, SIZE_T size, BOOLEAN executable)
{
    if (!va || size == 0 || !g_host_root_va)
        return TRUE;

    UINT64 start = ((UINT64)(ULONG_PTR)va) & ~0xFFFULL;
    UINT64 end   = (((UINT64)(ULONG_PTR)va + size - 1ULL) & ~0xFFFULL);

    for (UINT64 cur = start; cur <= end; cur += PAGE_SIZE)
    {
        UINT64 pa = va_to_pa((PVOID)(ULONG_PTR)cur);
        if (!pa)
            continue; // skip discarded/unmapped pages (e.g. INIT section)

        if (!hostcr3_map_page(cur, pa, executable))
            return FALSE;

        if (cur == ~0xFFFULL)
            break;
    }

    return TRUE;
}

BOOLEAN
hostcr3_build(VOID)
{
    if (!hostcr3_init())
        return FALSE;

    //
    // 1. map the entire driver image (code + .rdata + .data + g_host_idt + globals)
    //
    if (g_driver_base && g_driver_size)
    {
        if (!hostcr3_map_range(g_driver_base, g_driver_size, TRUE))
            goto fail;
    }

    //
    // 2. map g_vcpu array and all per-vCPU host-mode buffers
    //
    if (g_vcpu && g_vcpu_capacity)
    {
        if (!hostcr3_map_range(g_vcpu, sizeof(VIRTUAL_MACHINE_STATE) * g_vcpu_capacity, FALSE))
            goto fail;

        for (UINT32 i = 0; i < g_vcpu_capacity; i++)
        {
            VIRTUAL_MACHINE_STATE *vcpu = &g_vcpu[i];

            if (vcpu->vmm_stack &&
                !hostcr3_map_range((PVOID)vcpu->vmm_stack, VMM_STACK_SIZE, FALSE))
                goto fail;

            if (vcpu->host_gdt &&
                !hostcr3_map_range(vcpu->host_gdt, PAGE_SIZE, FALSE))
                goto fail;

            if (vcpu->vmcb_va &&
                !hostcr3_map_range((PVOID)vcpu->vmcb_va, VMCB_SIZE, FALSE))
                goto fail;

            if (vcpu->hsave_va &&
                !hostcr3_map_range((PVOID)vcpu->hsave_va, PAGE_SIZE, FALSE))
                goto fail;

            if (vcpu->svm_host_vmcb_va &&
                !hostcr3_map_range((PVOID)vcpu->svm_host_vmcb_va, PAGE_SIZE, FALSE))
                goto fail;

            if (vcpu->msr_bitmap_va &&
                !hostcr3_map_range((PVOID)vcpu->msr_bitmap_va, PAGE_SIZE, FALSE))
                goto fail;

            if (vcpu->msrpm_va &&
                !hostcr3_map_range((PVOID)vcpu->msrpm_va, MSRPM_SIZE, FALSE))
                goto fail;
        }
    }

    //
    // 3. map EPT/NPT state + page tables + DynPool + lock-free root log ring
    //
    if (!ept_map_into_hostcr3())
        goto fail;

    if (!logbuf_map_into_hostcr3())
        goto fail;

    HV_LOG("Minimal private host CR3 built: PA=0x%llx (%u pages, %s)\n",
           g_host_root_pa, g_host_pt_count, g_host_la57 ? "LA57 5-level" : "4-level");
    return TRUE;

fail:
    hostcr3_destroy();
    return FALSE;
}

UINT64
hostcr3_get(VOID)
{
    return g_host_root_pa;
}

VOID
hostcr3_destroy(VOID)
{
    for (UINT32 i = 0; i < g_host_pt_count; i++)
    {
        if (g_host_pt_pages[i].Va)
            hv_free_contiguous(g_host_pt_pages[i].Va);
    }

    g_host_pt_count = 0;
    g_host_root_va  = NULL;
    g_host_root_pa  = 0;
    g_host_la57     = FALSE;
}
