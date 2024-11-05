/** @file
  Barriers and synchronizaton primitives.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
--*/

#if defined(MDE_CPU_X64)

#ifdef _MSC_VER
#define MemoryBarrier() __faststorefence()
#else
#define MemoryBarrier() __asm__ __volatile__("sfence" ::: "memory")
#endif

static inline
INT32
ReadAcquire (
    IN  INT32 const volatile *Source
    )

{
    INT32 value;

    value = *Source;
    return value;
}

static inline
INT32
ReadNoFence (
    IN INT32 const volatile *Source
    )

{
    INT32 value;

    value = *Source;
    return value;
}

static inline
VOID
WriteNoFence (
    OUT INT32 volatile *Destination,
    IN  INT32 Value
    )

{

    *Destination = Value;
    return;
}

static inline
VOID
WriteNoFence16 (
    OUT INT16 volatile *Destination,
    IN  INT16 Value
    )

{

    *Destination = Value;
    return;
}

static inline
VOID
WriteRelease (
    OUT INT32 volatile *Destination,
    IN  INT32 Value
    )

{

    *Destination = Value;
    return;
}

#elif defined(MDE_CPU_AARCH64)

#pragma intrinsic(__dmb)

typedef enum _tag_ARM64INTR_BARRIER_TYPE
{
    _ARM64_BARRIER_SY    = 0xF,
    _ARM64_BARRIER_ST    = 0xE,
    _ARM64_BARRIER_LD    = 0xD,
    _ARM64_BARRIER_ISH   = 0xB,
    _ARM64_BARRIER_ISHST = 0xA,
    _ARM64_BARRIER_ISHLD = 0x9,
    _ARM64_BARRIER_NSH   = 0x7,
    _ARM64_BARRIER_NSHST = 0x6,
    _ARM64_BARRIER_NSHLD = 0x5,
    _ARM64_BARRIER_OSH   = 0x3,
    _ARM64_BARRIER_OSHST = 0x2,
    _ARM64_BARRIER_OSHLD = 0x1
}
_ARM64INTR_BARRIER_TYPE;

void __dmb(unsigned int _Type);

#define MemoryBarrier() __dmb(_ARM64_BARRIER_SY)

static inline
INT32
ReadAcquire (
    IN  INT32 const volatile *Source
    )

{
    INT32 value;

    value = __iso_volatile_load32((int *)Source);
    __dmb(_ARM64_BARRIER_ISH);
    return value;
}

static inline
INT32
ReadNoFence (
    IN  INT32 const volatile *Source
    )

{
    INT32 value;

    value = __iso_volatile_load32((int *)Source);
    return value;
}

static inline
VOID
WriteNoFence16 (
    OUT INT16 volatile *Destination,
    IN  INT16 Value
    )

{
    __iso_volatile_store16(Destination, Value);
    return;
}

static inline
VOID
WriteNoFence (
    OUT INT32 volatile *Destination,
    IN  INT32 Value
    )

{
    __iso_volatile_store32((int *)Destination, Value);
    return;
}

static inline
VOID
WriteRelease (
    OUT INT32 volatile *Destination,
    IN  INT32 Value
    )

{
    __dmb(_ARM64_BARRIER_ISH);
    __iso_volatile_store32((int *)Destination, Value);
    return;
}


#endif
