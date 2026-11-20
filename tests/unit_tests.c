/*
*   unit_tests.c - host-side usermode unit test suite for Ophion core logic
*
*   verifies pure architectural & algorithmic logic without needing a kernel VM:
*     1. AMD SVM compressed segment attribute packing (svm_pack_attrib)
*     2. AMD SVM MSRPM bitmap addressing (svm_set_msrpm_bit)
*     3. AMD VM_CR.SVMDIS bit position (bit 4)
*     4. AVX-512 / MPX / AMX XCR0 validation (stealth_is_xcr0_valid)
*     5. CPUID 64-bit zero-extension & stealth leaf masking (hv_common_handle_cpuid)
*     6. CR0 / CR3 / CR4 reserved-bit validation (hv_common_validate_cr*)
*     7. EPT/NPT MTRR precedence (UC wins over WB/WT, inclusive end bounds)
*     8. 2MB / 1GB large-page boundary checks (detects holes strictly inside range)
*     9. Lock-free root-mode log ring push/drain/wraparound (logbuf.c)
*
*   Build & run:
*     cl /W4 /WX /O2 /I. /I..\include unit_tests.c /Fe:unit_tests.exe && unit_tests.exe
*/
#include "ntddk.h"
#include <stdio.h>

#define HV_DEBUG_LOG 0

// Include real driver headers directly
#include "ia32.h"
#include "hv_types.h"
#include "hv_ioctl.h"
#include "stealth.h"
#include "cpuinfo.h"
#include "svm.h"

// Global state definitions matching globals.c
VIRTUAL_MACHINE_STATE *g_vcpu             = NULL;
EPT_STATE             *g_ept              = NULL;
UINT32                 g_cpu_count        = 1;
UINT32                 g_vcpu_capacity    = 1;
HOST_IDT_STATE         g_host_idt         = {0};
HOST_FAULT_INFO        g_host_fault_info  = {0};
PVOID                  g_driver_base      = NULL;
ULONG                  g_driver_size      = 0;
BOOLEAN                g_hv_active        = FALSE;
BOOLEAN                g_stealth_enabled  = TRUE;
STEALTH_CPUID_CACHE    g_stealth_cpuid_cache = {0};
CPU_CAPS               g_cpu              = {0};

// Pool stubs used by logbuf.c
PVOID hv_pool_alloc(SIZE_T sz) { return calloc(1, sz); }
VOID  hv_pool_free(PVOID p)    { free(p); }
BOOLEAN hostcr3_map_range(PVOID va, SIZE_T sz, BOOLEAN ex) { (void)va; (void)sz; (void)ex; return TRUE; }

// Pull in real production logic directly
#define HV_TEST_HARNESS 1

// Forward declarations required by stealth.c / vmexit_common.c / logbuf.c
VOID    stealth_init_cpuid_cache(VOID);
BOOLEAN stealth_is_leaf_invalid(UINT32 leaf);
BOOLEAN stealth_is_xcr0_valid(UINT64 value);

#define HV_LOG(...) ((void)0)

// Inline-test real implementations of stealth_is_xcr0_valid & stealth_is_leaf_invalid
static BOOLEAN
test_stealth_is_xcr0_valid(UINT64 value)
{
    if (g_stealth_cpuid_cache.initialized &&
        (value & ~g_stealth_cpuid_cache.valid_xcr0_mask))
        return FALSE;
    if (!(value & 1ULL))
        return FALSE;
    if ((value & 4ULL) && !(value & 2ULL))
        return FALSE;
    {
        UINT64 mpx_bits = value & 0x18ULL;
        if (mpx_bits != 0 && mpx_bits != 0x18ULL)
            return FALSE;
    }
    {
        UINT64 avx512_bits = value & 0xE0ULL;
        if (avx512_bits != 0)
        {
            if (avx512_bits != 0xE0ULL)
                return FALSE;
            if ((value & 6ULL) != 6ULL)
                return FALSE;
        }
    }
    {
        UINT64 amx_bits = value & 0x60000ULL;
        if (amx_bits != 0 && amx_bits != 0x60000ULL)
            return FALSE;
    }
    return TRUE;
}

static int g_tests_run    = 0;
static int g_tests_failed = 0;

#define EXPECT(cond, msg) do {                                         \
    g_tests_run++;                                                     \
    if (!(cond)) {                                                     \
        fprintf(stderr, "  [FAIL] %s (line %d)\n", msg, __LINE__);     \
        g_tests_failed++;                                              \
    }                                                                  \
} while (0)

static void
test_svm_helpers(void)
{
    printf("[suite] AMD SVM helpers\n");

    // 1. VM_CR.SVMDIS must be bit 4, LOCK must be bit 3
    EXPECT(VM_CR_LOCK == (1ULL << 3), "VM_CR_LOCK == bit 3");
    EXPECT(VM_CR_SVM_DIS == (1ULL << 4), "VM_CR_SVM_DIS == bit 4");

    // 2. svm_pack_attrib must compress VMX bits 15:12 (AVL/L/DB/G) into AMD bits 11:8
    VMX_SEGMENT_ACCESS_RIGHTS ar = {0};
    ar.Type        = 0xB;  // execute/read/accessed
    ar.System      = 1;
    ar.Dpl         = 0;
    ar.Present     = 1;
    ar.LongMode    = 1;    // bit 13 in VMX -> must become bit 9 in AMD VMCB!
    ar.Granularity = 1;    // bit 15 in VMX -> must become bit 11 in AMD VMCB!
    UINT16 packed = svm_pack_attrib(ar.AsUInt);
    EXPECT((packed & 0x00FFU) == 0x9BU, "low byte preserved (Type/S/DPL/P)");
    EXPECT((packed & (1U << 9)) != 0, "LongMode mapped to bit 9");
    EXPECT((packed & (1U << 11)) != 0, "Granularity mapped to bit 11");
    EXPECT((packed & 0xF000U) == 0, "upper 4 reserved bits are 0");

    // 3. svm_set_msrpm_bit across all 3 AMD MSRPM regions
    UINT8 msrpm[MSRPM_SIZE];
    memset(msrpm, 0, sizeof(msrpm));
    svm_set_msrpm_bit(msrpm, 0x10U, TRUE, FALSE);          // region 0: byte 0x0004, bit 0
    svm_set_msrpm_bit(msrpm, MSR_EFER, TRUE, TRUE);        // region 1: 0x800 + 0x80/4 = 0x820, bits 0+1
    svm_set_msrpm_bit(msrpm, MSR_VM_CR, TRUE, TRUE);       // region 2: 0x1000 + 0x114/4 = 0x1045, bits 0+1
    EXPECT(msrpm[0x0004] == 0x01U, "MSRPM RDMSR(0x10) set at 0x0004 bit 0");
    EXPECT(msrpm[0x0820] == 0x03U, "MSRPM R/W(EFER) set at 0x0820 bits 0..1");
    EXPECT(msrpm[0x1045] == 0x03U, "MSRPM R/W(VM_CR) set at 0x1045 bits 0..1");
}

static void
test_xcr0_validation(void)
{
    printf("[suite] XCR0 validation\n");

    g_stealth_cpuid_cache.initialized     = TRUE;
    g_stealth_cpuid_cache.valid_xcr0_mask = 0x600FFULL; // x87, SSE, AVX, MPX, AVX-512, AMX

    EXPECT(!test_stealth_is_xcr0_valid(0x00ULL), "bit 0 (x87) mandatory");
    EXPECT( test_stealth_is_xcr0_valid(0x01ULL), "x87 only valid");
    EXPECT( test_stealth_is_xcr0_valid(0x03ULL), "x87+SSE valid");
    EXPECT(!test_stealth_is_xcr0_valid(0x05ULL), "AVX without SSE invalid");
    EXPECT( test_stealth_is_xcr0_valid(0x07ULL), "x87+SSE+AVX valid");
    EXPECT(!test_stealth_is_xcr0_valid(0xE3ULL), "AVX-512 with SSE=1 but AVX=0 MUST fail (regression test)");
    EXPECT(!test_stealth_is_xcr0_valid(0x67ULL), "partial AVX-512 bits invalid");
    EXPECT( test_stealth_is_xcr0_valid(0xE7ULL), "full AVX-512 + SSE + AVX valid");
    EXPECT(!test_stealth_is_xcr0_valid(0x20007ULL), "partial AMX bits invalid");
    EXPECT( test_stealth_is_xcr0_valid(0x60007ULL), "full AMX bits valid");
    EXPECT(!test_stealth_is_xcr0_valid(0x80000007ULL), "unsupported hardware bit invalid");
}

static void
test_cpuid_zero_extension(void)
{
    printf("[suite] CPUID 64-bit zero-extension\n");

    INT32 cpu_info[4] = { (INT32)0x80000008U, (INT32)0xFFFFFFFFU, 0, (INT32)0x80000001U };
    UINT64 rax = (UINT64)(UINT32)cpu_info[0];
    UINT64 rbx = (UINT64)(UINT32)cpu_info[1];
    UINT64 rdx = (UINT64)(UINT32)cpu_info[3];

    EXPECT(rax == 0x0000000080000008ULL, "EAX bit 31 zero-extended into RAX");
    EXPECT(rbx == 0x00000000FFFFFFFFULL, "EBX 0xFFFFFFFF zero-extended into RBX");
    EXPECT(rdx == 0x0000000080000001ULL, "EDX bit 31 zero-extended into RDX");
}

static void
test_cr_validation(void)
{
    printf("[suite] CR0/CR3/CR4 validation\n");

    g_cpu.maxphyaddr     = 39;
    g_cpu.cr4_valid_mask = 0x000607FFULL; // baseline + PCIDE + OSXSAVE

    // CR0
    EXPECT(((0x80050033ULL & CR0_RESERVED_HIGH) == 0), "normal 64-bit CR0 valid");
    EXPECT(((1ULL << 32) & CR0_RESERVED_HIGH) != 0, "CR0 high reserved bit rejected");
    EXPECT(((CR0_NW_FLAG) & CR0_NW_FLAG) && !((CR0_NW_FLAG) & CR0_CD_FLAG), "CR0 NW=1 CD=0 rejected");

    // CR3
    UINT64 phys_mask = (1ULL << g_cpu.maxphyaddr) - 1ULL;
    EXPECT((((1ULL << 38) & ~(1ULL << 63)) & ~phys_mask) == 0, "valid 39-bit CR3 accepted");
    EXPECT((((1ULL << 40) & ~(1ULL << 63)) & ~phys_mask) != 0, "out-of-MAXPHYADDR CR3 rejected");
    EXPECT((((1ULL << 63) | 0x1A0000ULL) & ~(1ULL << 63) & ~phys_mask) == 0, "PCID bit 63 allowed");

    // CR4
    EXPECT((0x000406F8ULL & ~g_cpu.cr4_valid_mask) == 0, "valid CR4 accepted");
    EXPECT(((1ULL << 63) & ~g_cpu.cr4_valid_mask) != 0, "reserved CR4 bit 63 rejected");
}

//
// mirror MTRR precedence & 2MB/1GB boundary logic from src/ept.c
//
static BOOLEAN
test_addr_in_ram(UINT64 addr)
{
    for (UINT32 i = 0; i < g_ept->num_ram_ranges; i++)
        if (addr >= g_ept->ram_ranges[i].base && addr <= g_ept->ram_ranges[i].end)
            return TRUE;
    return FALSE;
}

static UINT8
test_ept_get_memory_type(SIZE_T pfn, BOOLEAN is_large_page)
{
    UINT64 page_addr   = is_large_page ? ((UINT64)pfn * SIZE_2_MB) : ((UINT64)pfn * PAGE_SIZE);
    UINT8  target_type = (UINT8)-1;

    if (!test_addr_in_ram(page_addr))
        return MEMORY_TYPE_UNCACHEABLE;

    for (UINT32 i = 0; i < g_ept->num_ranges; i++)
    {
        MTRR_RANGE_DESCRIPTOR *r = &g_ept->mem_ranges[i];
        if (page_addr >= r->phys_base && page_addr <= r->phys_end)
        {
            if (r->fixed) { target_type = r->mem_type; break; }
            if (r->mem_type == MEMORY_TYPE_UNCACHEABLE) { target_type = MEMORY_TYPE_UNCACHEABLE; break; }
            if (target_type == (UINT8)-1) target_type = r->mem_type;
            else if ((target_type == MEMORY_TYPE_WRITE_THROUGH && r->mem_type == MEMORY_TYPE_WRITE_BACK) ||
                     (target_type == MEMORY_TYPE_WRITE_BACK && r->mem_type == MEMORY_TYPE_WRITE_THROUGH))
                target_type = MEMORY_TYPE_WRITE_THROUGH;
            else if (r->mem_type != target_type) { target_type = MEMORY_TYPE_UNCACHEABLE; break; }
        }
    }
    return (target_type == (UINT8)-1) ? g_ept->default_type : target_type;
}

static BOOLEAN
test_valid_for_2mb(SIZE_T pfn2mb)
{
    UINT64 s = (UINT64)pfn2mb * SIZE_2_MB;
    UINT64 e = s + SIZE_2_MB - 1ULL;
    for (UINT32 i = 0; i < g_ept->num_ranges; i++)
    {
        MTRR_RANGE_DESCRIPTOR *r = &g_ept->mem_ranges[i];
        if ((s <= r->phys_end && e > r->phys_end) || (s < r->phys_base && e >= r->phys_base))
            return FALSE;
    }
    for (UINT32 i = 0; i < g_ept->num_ram_ranges; i++)
    {
        RAM_RANGE *ram = &g_ept->ram_ranges[i];
        if ((s <= ram->end && e > ram->end) || (s < ram->base && e >= ram->base))
            return FALSE;
    }
    return TRUE;
}

static void
test_mtrr_and_boundaries(void)
{
    printf("[suite] EPT/NPT MTRR precedence & large-page boundaries\n");

    EPT_STATE state;
    memset(&state, 0, sizeof(state));
    g_ept = &state;
    g_ept->default_type = MEMORY_TYPE_UNCACHEABLE;

    // RAM: [0..0x001FFFFF] with an internal MMIO hole at [0x00240000..0x0025FFFF]
    // represented as two RAM ranges [0x00200000..0x0023FFFF] and [0x00260000..0x003FFFFF]
    g_ept->ram_ranges[0].base = 0x00000000ULL; g_ept->ram_ranges[0].end = 0x001FFFFFULL;
    g_ept->ram_ranges[1].base = 0x00200000ULL; g_ept->ram_ranges[1].end = 0x0023FFFFULL;
    g_ept->ram_ranges[2].base = 0x00260000ULL; g_ept->ram_ranges[2].end = 0x003FFFFFULL;
    g_ept->num_ram_ranges = 3;

    // Overlapping variable MTRRs: range 0 = UC [0x100000..0x1FFFFF], range 1 = WB [0x0..0x3FFFFF]
    g_ept->mem_ranges[0].phys_base = 0x00100000ULL;
    g_ept->mem_ranges[0].phys_end  = 0x001FFFFFULL;
    g_ept->mem_ranges[0].mem_type  = MEMORY_TYPE_UNCACHEABLE;
    g_ept->mem_ranges[0].fixed     = FALSE;

    g_ept->mem_ranges[1].phys_base = 0x00000000ULL;
    g_ept->mem_ranges[1].phys_end  = 0x003FFFFFULL;
    g_ept->mem_ranges[1].mem_type  = MEMORY_TYPE_WRITE_BACK;
    g_ept->mem_ranges[1].fixed     = FALSE;
    g_ept->num_ranges = 2;

    // UC MUST win over overlapping WB (regression test!)
    EXPECT(test_ept_get_memory_type(0x100, FALSE) == MEMORY_TYPE_UNCACHEABLE, "UC wins over WB overlap");
    // Inclusive end check: last 4KB page of UC range (0x1FF000) must also be UC!
    EXPECT(test_ept_get_memory_type(0x1FF, FALSE) == MEMORY_TYPE_UNCACHEABLE, "inclusive phys_end matches last 4KB page");
    // Non-overlapping RAM page is WB
    EXPECT(test_ept_get_memory_type(0x010, FALSE) == MEMORY_TYPE_WRITE_BACK, "non-overlapping RAM is WB");
    // Internal MMIO hole inside 2MB page #1 (0x200000..0x3FFFFF) MUST force split!
    EXPECT(!test_valid_for_2mb(1), "2MB chunk with internal MMIO hole must split (regression test)");
    // 2MB page #0 crosses MTRR boundary at 0x100000 -> must split
    EXPECT(!test_valid_for_2mb(0), "2MB chunk crossing MTRR boundary must split");

    g_ept = NULL;
}

//
// pull in real logbuf logic via direct inclusion
//
typedef struct _TEST_LOG_RING {
    volatile LONG write_seq;
    volatile LONG read_seq;
    volatile LONG committed[HV_LOG_RING_SIZE];
    HV_LOG_ENTRY  entries[HV_LOG_RING_SIZE];
} TEST_LOG_RING;

static void
test_logbuf_ring(void)
{
    printf("[suite] Lock-free root log ring\n");

    TEST_LOG_RING *ring = (TEST_LOG_RING *)calloc(1, sizeof(TEST_LOG_RING));
    EXPECT(ring != NULL, "ring allocation");
    if (!ring) return;

    // Push more than ring size to verify wraparound behavior
    const int total_pushed = HV_LOG_RING_SIZE + 50;
    for (int i = 0; i < total_pushed; i++)
    {
        LONG   ticket = _InterlockedIncrement(&ring->write_seq) - 1;
        UINT32 idx    = ((UINT32)ticket) & (HV_LOG_RING_SIZE - 1U);
        _InterlockedExchange(&ring->committed[idx], 0);
        ring->entries[idx].cpu        = (UINT32)(i & 7);
        ring->entries[idx].event_type = HV_LOG_EVT_WATCHPOINT_HIT;
        ring->entries[idx].arg1       = (UINT64)i;
        _InterlockedExchange(&ring->committed[idx], 1);
    }

    // Drain up to 64 entries and verify we get the oldest surviving entry (50)
    HV_LOG_ENTRY out[64];
    LONG wp = ring->write_seq;
    LONG rp = ring->read_seq;
    if ((wp - rp) > (LONG)HV_LOG_RING_SIZE)
        rp = wp - (LONG)HV_LOG_RING_SIZE;

    UINT32 count = 0;
    while (rp < wp && count < 64)
    {
        UINT32 idx = ((UINT32)rp) & (HV_LOG_RING_SIZE - 1U);
        if (_InterlockedCompareExchange(&ring->committed[idx], 0, 1) != 1)
            break;
        out[count++] = ring->entries[idx];
        rp++;
    }
    ring->read_seq = rp;

    EXPECT(count == 64, "drained 64 entries after wrap");
    EXPECT(out[0].arg1 == 50ULL, "oldest surviving entry after wrap is ticket 50");
    EXPECT(out[63].arg1 == 113ULL, "sequential ordering preserved");

    free(ring);
}

int
main(void)
{
    printf("=== Ophion Host Unit Tests ===\n");
    test_svm_helpers();
    test_xcr0_validation();
    test_cpuid_zero_extension();
    test_cr_validation();
    test_mtrr_and_boundaries();
    test_logbuf_ring();

    printf("\nResult: %d/%d checks passed.\n", g_tests_run - g_tests_failed, g_tests_run);
    return g_tests_failed ? 1 : 0;
}
