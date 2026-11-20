/*
*   hostidt.c - private host IDT for VMX-root / SVM host mode
*   prevents NMI hijacking where guest corrupts OS IDT and triggers
*   NMI while in host mode to execute attacker code in ring 0.
*
*   NOTE: original per-core IDTR base/limit are stored per-vCPU (not globally)
*   because Windows 10/11 maintain per-processor IDTs.
*/
#include "hv.h"

static VOID
hostidt_set_gate(
    PIDT_GATE_DESCRIPTOR_64 gate,
    UINT64                  handler,
    UINT16                  selector,
    UINT8                   type,
    UINT8                   ist
)
{
    gate->OffsetLow  = (UINT16)(handler & 0xFFFF);
    gate->OffsetMid  = (UINT16)((handler >> 16) & 0xFFFF);
    gate->OffsetHigh = (UINT32)(handler >> 32);
    gate->Selector   = selector;
    gate->Ist        = ist;
    gate->Reserved0  = 0;
    gate->Type       = type;
    gate->Zero       = 0;
    gate->Dpl        = 0;
    gate->Present    = 1;
    gate->Reserved1  = 0;
}

BOOLEAN
hostidt_build(VOID)
{
    UINT16 cs;

    if (g_host_idt.initialized)
        return TRUE;

    cs = asm_get_cs() & 0xF8;

    RtlZeroMemory(&g_host_fault_info, sizeof(g_host_fault_info));

    //
    // default handler records fault context and halts cpu
    //
    for (UINT32 i = 0; i < IDT_NUM_ENTRIES; i++)
        hostidt_set_gate(&g_host_idt.idt[i], (UINT64)asm_host_default_handler, cs, IDT_TYPE_INTERRUPT_GATE, 0);

    //
    // NMI: atomically sets the per-core pending flag at the top of the
    // 32KB-aligned VMM stack; the VM-exit handler injects NMI on that core.
    //
    hostidt_set_gate(&g_host_idt.idt[IDT_VECTOR_NMI], (UINT64)asm_host_nmi_handler, cs, IDT_TYPE_INTERRUPT_GATE, 0);

    //
    // #DF / #GP / #PF: record diagnostic snapshot in g_host_fault_info and halt
    //
    hostidt_set_gate(&g_host_idt.idt[IDT_VECTOR_DF], (UINT64)asm_host_df_handler, cs, IDT_TYPE_INTERRUPT_GATE, 0);
    hostidt_set_gate(&g_host_idt.idt[IDT_VECTOR_GP], (UINT64)asm_host_gp_handler, cs, IDT_TYPE_INTERRUPT_GATE, 0);
    hostidt_set_gate(&g_host_idt.idt[IDT_VECTOR_PF], (UINT64)asm_host_pf_handler, cs, IDT_TYPE_INTERRUPT_GATE, 0);

    g_host_idt.initialized = TRUE;
    return TRUE;
}

UINT64
hostidt_get_base(VOID)
{
    return (UINT64)&g_host_idt.idt[0];
}

VOID
hostidt_destroy(VOID)
{
    g_host_idt.initialized = FALSE;
}
