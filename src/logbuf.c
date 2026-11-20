/*
*   logbuf.c - lock-free root-mode ring-buffer logger
*
*   allows VMX-root / SVM-host exit handlers to record structured diagnostic
*   events (watchpoint hits, dynamic MMIO maps, MSR traces, unhandled exits)
*   with ZERO Windows API calls and ZERO blocking locks.
*
*   drained safely at PASSIVE_LEVEL via IOCTL_HV_DRAIN_LOGS.
*/
#include "hv.h"

typedef struct _HV_LOG_RING {
    volatile LONG write_seq;    // monotonically increasing slot ticket
    volatile LONG read_seq;     // consumer cursor
    volatile LONG committed[HV_LOG_RING_SIZE]; // 1 once entry write is complete
    HV_LOG_ENTRY  entries[HV_LOG_RING_SIZE];
} HV_LOG_RING, *PHV_LOG_RING;

static PHV_LOG_RING g_log_ring = NULL;

BOOLEAN
logbuf_init(VOID)
{
    if (g_log_ring)
        return TRUE;

    g_log_ring = (PHV_LOG_RING)hv_pool_alloc(sizeof(HV_LOG_RING));
    if (!g_log_ring)
        return FALSE;

    RtlZeroMemory(g_log_ring, sizeof(HV_LOG_RING));
    return TRUE;
}

VOID
logbuf_destroy(VOID)
{
    if (g_log_ring)
    {
        hv_pool_free(g_log_ring);
        g_log_ring = NULL;
    }
}

BOOLEAN
logbuf_map_into_hostcr3(VOID)
{
    if (!g_log_ring)
        return TRUE;

    return hostcr3_map_range(g_log_ring, sizeof(HV_LOG_RING), FALSE);
}

//
// root-mode-safe producer: single atomic increment claims a slot.
// if the ring wraps faster than the consumer drains it, oldest entries are
// overwritten cleanly (never blocks or stalls a vCPU).
//
VOID
logbuf_push_root(UINT32 cpu, UINT32 event_type, UINT64 arg1, UINT64 arg2)
{
    if (!g_log_ring)
        return;

    LONG   ticket = _InterlockedIncrement(&g_log_ring->write_seq) - 1;
    UINT32 idx    = ((UINT32)ticket) & (HV_LOG_RING_SIZE - 1U);

    //
    // mark slot in-progress while populating
    //
    _InterlockedExchange(&g_log_ring->committed[idx], 0);

    HV_LOG_ENTRY *e = &g_log_ring->entries[idx];
    e->tsc        = __rdtsc();
    e->cpu        = cpu;
    e->event_type = event_type;
    e->arg1       = arg1;
    e->arg2       = arg2;

    //
    // publish slot (release semantics via interlocked op)
    //
    _InterlockedExchange(&g_log_ring->committed[idx], 1);
}

//
// non-root consumer: drains up to max_entries into out_entries.
//
UINT32
logbuf_drain(PHV_LOG_ENTRY out_entries, UINT32 max_entries)
{
    if (!g_log_ring || !out_entries || max_entries == 0)
        return 0;

    LONG write_pos = _InterlockedCompareExchange(&g_log_ring->write_seq, 0, 0);
    LONG read_pos  = _InterlockedCompareExchange(&g_log_ring->read_seq, 0, 0);

    //
    // if producer wrapped past consumer by more than ring size, advance read_pos
    //
    if ((write_pos - read_pos) > (LONG)HV_LOG_RING_SIZE)
        read_pos = write_pos - (LONG)HV_LOG_RING_SIZE;

    UINT32 count = 0;
    while (read_pos < write_pos && count < max_entries)
    {
        UINT32 idx = ((UINT32)read_pos) & (HV_LOG_RING_SIZE - 1U);
        if (_InterlockedCompareExchange(&g_log_ring->committed[idx], 0, 1) != 1)
            break; // slot still being written by a vCPU

        out_entries[count++] = g_log_ring->entries[idx];
        read_pos++;
    }

    _InterlockedExchange(&g_log_ring->read_seq, read_pos);
    return count;
}
