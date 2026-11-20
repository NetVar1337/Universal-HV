/*
*   hostgdt.c - per-core private host GDT for VMX-root / SVM host mode
*
*   allocation happens at PASSIVE_LEVEL before hostcr3_build() so every
*   vcpu->host_gdt page is guaranteed mapped in the private host CR3.
*   population copies each core's live GDT when initializing that core.
*/
#include "hv.h"

BOOLEAN
hostgdt_alloc_for_vcpu(VIRTUAL_MACHINE_STATE * vcpu)
{
    if (vcpu->host_gdt)
        return TRUE;

    PVOID gdt_copy = hv_alloc_contiguous(PAGE_SIZE);
    if (!gdt_copy)
        return FALSE;

    RtlZeroMemory(gdt_copy, PAGE_SIZE);
    vcpu->host_gdt = gdt_copy;
    return TRUE;
}

BOOLEAN
hostgdt_populate_for_vcpu(VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT64 orig_base  = asm_get_gdt_base();
    UINT16 orig_limit = asm_get_gdt_limit();
    SIZE_T copy_len   = (SIZE_T)orig_limit + 1;

    vcpu->original_gdt_base    = orig_base;
    vcpu->original_gdt_limit   = orig_limit;
    vcpu->original_tr_selector = asm_get_tr();

    if (!vcpu->host_gdt)
        return FALSE;

    if (copy_len > PAGE_SIZE)
        copy_len = PAGE_SIZE;

    RtlZeroMemory(vcpu->host_gdt, PAGE_SIZE);
    RtlCopyMemory(vcpu->host_gdt, (PVOID)orig_base, copy_len);
    return TRUE;
}

VOID
hostgdt_destroy_for_vcpu(VIRTUAL_MACHINE_STATE * vcpu)
{
    if (vcpu->host_gdt)
    {
        hv_free_contiguous(vcpu->host_gdt);
        vcpu->host_gdt = NULL;
    }
}
