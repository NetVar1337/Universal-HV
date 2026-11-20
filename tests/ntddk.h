/*
*   tests/ntddk.h - minimal usermode shim for host-side unit tests ONLY
*   (not included in Ophion.vcxproj kernel driver builds).
*/
#pragma once

#include <windows.h>
#include <intrin.h>
#include <stdlib.h>
#include <string.h>

#ifndef NTKERNELAPI
#define NTKERNELAPI
#endif

#ifndef DPFLTR_IHVDRIVER_ID
#define DPFLTR_IHVDRIVER_ID 0
#define DPFLTR_INFO_LEVEL   0
#endif

#ifndef DbgPrintEx
#define DbgPrintEx(...) ((void)0)
#endif

#ifndef NonPagedPool
#define NonPagedPool 0
#endif

#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED 0
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

typedef LONG           NTSTATUS;
typedef ULONG64        POOL_FLAGS;
typedef LARGE_INTEGER  PHYSICAL_ADDRESS;
typedef UCHAR          KIRQL;

typedef struct _PHYSICAL_MEMORY_RANGE {
    PHYSICAL_ADDRESS BaseAddress;
    LARGE_INTEGER    NumberOfBytes;
} PHYSICAL_MEMORY_RANGE, *PPHYSICAL_MEMORY_RANGE;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _DRIVER_OBJECT *PDRIVER_OBJECT;

static __inline VOID
InitializeListHead(PLIST_ENTRY h)
{
    h->Flink = h->Blink = h;
}
