/*
*   svm.h - AMD SVM (AMD-V) definitions
*
*   reference: AMD64 Architecture Programmer's Manual Vol 2 (SVM chapter),
*   cross-checked against the Linux kernel's arch/x86/include/asm/svm.h.
*
*   the VMCB is one 4KB page:
*     0x000-0x3FF  control area
*     0x400-0xFFF  state save area
*/
#pragma once

#include <ntddk.h>

//
// MSRs (already partially in cpuinfo.h; keep all SVM MSRs here)
//
#ifndef MSR_EFER
#define MSR_EFER                0xC0000080
#endif
#ifndef EFER_SVME
#define EFER_SVME               (1ULL << 12)
#endif
#ifndef MSR_VM_CR
#define MSR_VM_CR               0xC0010114
#endif
#ifndef MSR_VM_HSAVE_PA
#define MSR_VM_HSAVE_PA         0xC0010117
#endif

//
// VMCB control area offsets
//
#define VMCB_CTRL_INTERCEPT_WORD0   0x00    // CR reads (bit n) / CR writes (bit 16+n)
#define VMCB_CTRL_INTERCEPT_WORD1   0x04    // DR reads (bit n) / DR writes (bit 16+n)
#define VMCB_CTRL_INTERCEPT_WORD2   0x08    // exception intercepts (bit = vector)
#define VMCB_CTRL_INTERCEPT_WORD3   0x0C    // misc instruction intercepts
#define VMCB_CTRL_INTERCEPT_WORD4   0x10    // VMX-equivalent SVM instructions etc.
#define VMCB_CTRL_INTERCEPT_WORD5   0x14
#define VMCB_CTRL_IOPM_BASE_PA      0x40
#define VMCB_CTRL_MSRPM_BASE_PA     0x48
#define VMCB_CTRL_TSC_OFFSET        0x50
#define VMCB_CTRL_ASID              0x58
#define VMCB_CTRL_TLB_CTL           0x5C
#define VMCB_CTRL_INT_CTL           0x60    // V_TPR[3:0], V_IRQ, V_GIF, ...
#define VMCB_CTRL_INT_VECTOR        0x64
#define VMCB_CTRL_INT_STATE         0x68
#define VMCB_CTRL_EXIT_CODE         0x70
#define VMCB_CTRL_EXIT_INFO1        0x78
#define VMCB_CTRL_EXIT_INFO2        0x80
#define VMCB_CTRL_EXIT_INT_INFO     0x88
#define VMCB_CTRL_EXIT_INT_INFO_ERR 0x8C
#define VMCB_CTRL_MISC_CTL          0x90    // bit0 = enable nested paging
#define VMCB_CTRL_EVENT_INJ         0xA8
#define VMCB_CTRL_EVENT_INJ_ERR     0xAC
#define VMCB_CTRL_NESTED_CR3        0xB0    // NPT PML4 physical address
#define VMCB_CTRL_CLEAN             0xC0
#define VMCB_CTRL_NEXT_RIP          0xC8
#define VMCB_CTRL_INSN_LEN          0xD0
#define VMCB_CTRL_INSN_BYTES        0xD1

//
// intercept bit positions (absolute bit index within the 6 intercept words)
//
#define SVM_INT_CR0_READ            0
#define SVM_INT_CR3_READ            3
#define SVM_INT_CR4_READ            4
#define SVM_INT_CR8_READ            8
#define SVM_INT_CR0_WRITE           16
#define SVM_INT_CR3_WRITE           19
#define SVM_INT_CR4_WRITE           20
#define SVM_INT_CR8_WRITE           24
#define SVM_INT_DR0_READ            32
#define SVM_INT_DR7_READ            39
#define SVM_INT_DR0_WRITE           48
#define SVM_INT_DR7_WRITE           55
#define SVM_INT_EXCEPTION_BASE      64      // + vector
#define SVM_INT_INTR                96
#define SVM_INT_NMI                 97
#define SVM_INT_RDTSC               110
#define SVM_INT_RDPMC               111
#define SVM_INT_CPUID               114
#define SVM_INT_INVD                118
#define SVM_INT_PAUSE               119
#define SVM_INT_HLT                 120
#define SVM_INT_INVLPG              121
#define SVM_INT_IOIO_PROT           123
#define SVM_INT_MSR_PROT            124
#define SVM_INT_SHUTDOWN            127
#define SVM_INT_VMRUN               128
#define SVM_INT_VMMCALL             129
#define SVM_INT_VMLOAD              130
#define SVM_INT_VMSAVE              131
#define SVM_INT_STGI                132
#define SVM_INT_CLGI                133
#define SVM_INT_SKINIT              134
#define SVM_INT_RDTSCP              135
#define SVM_INT_WBINVD              137
#define SVM_INT_XSETBV              141
#define SVM_INT_EFER_WRITE_TRAP     143
#define SVM_INT_CR0_WRITE_TRAP      144
#define SVM_INT_CR3_WRITE_TRAP      147
#define SVM_INT_CR4_WRITE_TRAP      148
#define SVM_INT_CR8_WRITE_TRAP      152
#define SVM_INT_INVPCID             162

//
// TLB control values
//
#define SVM_TLB_DO_NOTHING          0
#define SVM_TLB_FLUSH_ALL_ASID      1
#define SVM_TLB_FLUSH_ASID          3

//
// INT_CTL bits
//
#define SVM_V_TPR_MASK              0x0F
#define SVM_V_IRQ                   (1U << 8)
#define SVM_V_GIF                   (1U << 9)
#define SVM_V_INTR_MASKING          (1U << 24)
#define SVM_V_GIF_ENABLE            (1U << 25)
#define SVM_V_NMI_ENABLE            (1U << 26)

//
// MISC_CTL bits
//
#define SVM_MISC_ENABLE_NP          (1ULL << 0)

//
// event injection (EVENT_INJ) format
//
#define SVM_EVTINJ_VEC_MASK         0xFF
#define SVM_EVTINJ_TYPE_SHIFT       8
#define SVM_EVTINJ_TYPE_INTR        (0U << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_NMI         (2U << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_EXEPT       (3U << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_SOFT        (4U << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_VALID            (1U << 31)
#define SVM_EVTINJ_VALID_ERR        (1U << 11)

//
// #VMEXIT exit codes
//
#define SVM_EXIT_READ_CR0           0x000
#define SVM_EXIT_READ_CR3           0x003
#define SVM_EXIT_READ_CR4           0x004
#define SVM_EXIT_READ_CR8           0x008
#define SVM_EXIT_WRITE_CR0          0x010
#define SVM_EXIT_WRITE_CR3          0x013
#define SVM_EXIT_WRITE_CR4          0x014
#define SVM_EXIT_WRITE_CR8          0x018
#define SVM_EXIT_READ_DR0           0x020
#define SVM_EXIT_READ_DR7           0x027
#define SVM_EXIT_WRITE_DR0          0x030
#define SVM_EXIT_WRITE_DR7          0x037
#define SVM_EXIT_EXCP_BASE          0x040   // + exception vector
#define SVM_EXIT_INTR               0x060
#define SVM_EXIT_NMI                0x061
#define SVM_EXIT_SMI                0x062
#define SVM_EXIT_VINTR              0x064
#define SVM_EXIT_RDTSC              0x06E
#define SVM_EXIT_RDPMC              0x06F
#define SVM_EXIT_PUSHF              0x070
#define SVM_EXIT_POPF               0x071
#define SVM_EXIT_CPUID              0x072
#define SVM_EXIT_IRET               0x074
#define SVM_EXIT_INVD               0x076
#define SVM_EXIT_PAUSE              0x077
#define SVM_EXIT_HLT                0x078
#define SVM_EXIT_INVLPG             0x079
#define SVM_EXIT_IOIO               0x07B
#define SVM_EXIT_MSR                0x07C
#define SVM_EXIT_SHUTDOWN           0x07F
#define SVM_EXIT_VMRUN              0x080
#define SVM_EXIT_VMMCALL            0x081
#define SVM_EXIT_VMLOAD             0x082
#define SVM_EXIT_VMSAVE             0x083
#define SVM_EXIT_STGI               0x084
#define SVM_EXIT_CLGI               0x085
#define SVM_EXIT_SKINIT             0x086
#define SVM_EXIT_RDTSCP             0x087
#define SVM_EXIT_WBINVD             0x089
#define SVM_EXIT_MONITOR            0x08A
#define SVM_EXIT_MWAIT              0x08B
#define SVM_EXIT_XSETBV             0x08D
#define SVM_EXIT_EFER_WRITE_TRAP    0x08F
#define SVM_EXIT_CR0_WRITE_TRAP     0x090
#define SVM_EXIT_CR3_WRITE_TRAP     0x093
#define SVM_EXIT_CR4_WRITE_TRAP     0x094
#define SVM_EXIT_CR8_WRITE_TRAP     0x098
#define SVM_EXIT_INVPCID            0x0A2
#define SVM_EXIT_NPF                0x400   // nested page fault

//
// exit info 1 register selector mask (CR/DR exits)
//
#define SVM_EXITINFO_REG_MASK       0x0F

//
// segment descriptor in VMCB save area (16 bytes)
//
#pragma pack(push, 1)
typedef struct _SVM_SEGMENT {
    UINT16 Selector;
    UINT16 Attrib;      // same 16-bit access-rights layout as VMX
    UINT32 Limit;
    UINT64 Base;
} SVM_SEGMENT, *PSVM_SEGMENT;

//
// VMCB state save area (offset 0x400 within the VMCB page)
//
typedef struct _SVM_SAVE_AREA {
    SVM_SEGMENT Es;             // 0x400
    SVM_SEGMENT Cs;             // 0x410
    SVM_SEGMENT Ss;             // 0x420
    SVM_SEGMENT Ds;             // 0x430
    SVM_SEGMENT Fs;             // 0x440
    SVM_SEGMENT Gs;             // 0x450
    SVM_SEGMENT Gdtr;           // 0x460
    SVM_SEGMENT Ldtr;           // 0x470
    SVM_SEGMENT Idtr;           // 0x480
    SVM_SEGMENT Tr;             // 0x490
    UINT8      Reserved0[42];   // 0x4A0
    UINT8      Vmpl;            // 0x4CA
    UINT8      Cpl;             // 0x4CB
    UINT8      Reserved1[4];    // 0x4CC
    UINT64     Efer;            // 0x4D0
    UINT8      Reserved2[112];  // 0x4D8
    UINT64     Cr4;             // 0x548
    UINT64     Cr3;             // 0x550
    UINT64     Cr0;             // 0x558
    UINT64     Dr7;             // 0x560
    UINT64     Dr6;             // 0x568
    UINT64     Rflags;          // 0x570
    UINT64     Rip;             // 0x578
    UINT8      Reserved3[88];   // 0x580
    UINT64     Rsp;             // 0x5D8
    UINT64     SCet;            // 0x5E0
    UINT8      Reserved4[24];   // 0x5E8
    UINT64     Rax;             // 0x5F8
} SVM_SAVE_AREA, *PSVM_SAVE_AREA;

//
// full VMCB: control area (1KB) + save area (3KB) in one 4KB page
//
typedef struct _VMCB {
    UINT8      Control[0x400];
    SVM_SAVE_AREA Save;
} VMCB, *PVMCB;

//
// host save area (pointed to by MSR_VM_HSAVE_PA) uses the same layout as
// the save area for the fields VMRUN saves/restores.
//
typedef SVM_SAVE_AREA SVM_HOST_SAVE_AREA, *PSVM_HOST_SAVE_AREA;

#define SVM_HSAVE_OFF_CS        0x10
#define SVM_HSAVE_OFF_SS        0x20
#define SVM_HSAVE_OFF_ES        0x00
#define SVM_HSAVE_OFF_DS        0x30
#define SVM_HSAVE_OFF_GDTR      0x60
#define SVM_HSAVE_OFF_IDTR      0x80
#define SVM_HSAVE_OFF_EFER      0xD0
#define SVM_HSAVE_OFF_CR4       0x148
#define SVM_HSAVE_OFF_CR3       0x150
#define SVM_HSAVE_OFF_CR0       0x158
#define SVM_HSAVE_OFF_RFLAGS    0x170
#define SVM_HSAVE_OFF_RIP       0x178
#define SVM_HSAVE_OFF_RSP       0x1D8
#define SVM_HSAVE_OFF_RAX       0x1F8
#pragma pack(pop)

//
// helpers to poke control-area fields
//
static __forceinline VOID
svm_set_intercept(PVMCB vmcb, UINT32 bit)
{
    ((PUINT32)vmcb->Control)[bit >> 5] |= (1U << (bit & 31));
}

static __forceinline VOID
svm_clear_all_intercepts(PVMCB vmcb)
{
    RtlZeroMemory(vmcb->Control, 0x18);     // words 0-5 only
    //
    // leave IOPM/MSRPM/TSC/ASID/TLB/int/exit fields intact — clearing
    // intercepts only stops #VMEXITs, the rest of the control area stays.
    //
}

static __forceinline UINT64
svm_ctrl_read(PVMCB vmcb, UINT32 offset)
{
    return *(UINT64 *)((PUINT8)vmcb->Control + offset);
}

static __forceinline VOID
svm_ctrl_write(PVMCB vmcb, UINT32 offset, UINT64 value)
{
    *(UINT64 *)((PUINT8)vmcb->Control + offset) = value;
}

static __forceinline VOID
svm_ctrl_write32(PVMCB vmcb, UINT32 offset, UINT32 value)
{
    *(UINT32 *)((PUINT8)vmcb->Control + offset) = value;
}
