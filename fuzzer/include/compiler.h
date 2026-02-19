#pragma once
// Instructions after the barrier can not be moved before the barrier by the compiler.
#define barrier() asm volatile("" ::: "memory")

#define ACCESS_ONCE(x) (*(volatile typeof(x) *) &(x))
#define ARR_SZ(a)      (sizeof(a) / sizeof(*a))

#define _ptr(val) ((void *) (unsigned long) (val))
#define _ul(val)  ((unsigned long) (val))
#define _u(val)   ((unsigned int) (val))
#define _int(val) ((int) (val))

#define __used     __attribute__((__used__))
#define __noinline __attribute__((__noinline__))

#define KB(x) (_ul(x) << 10)
#define MB(x) (_ul(x) << 20)
#define GB(x) (_ul(x) << 30)

#define MSB64(val) (63 - __builtin_clzll(val))
#define MSB32(val) (31 - __builtin_clz(val))

/* Most significant bit of a 64- or 32-bit value. */
#define MSB(val) (sizeof(val) == 8 ? MSB64(val) : MSB32(val))
/* Least significant bit of a 64- or 32-bit value. */
#define LSB(val) (__builtin_ctz(val))

#define ALIGN(val, alignment) _ptr((_ul(val) & ~(alignment - 1)))
#define PG_ALIGN(val)         ALIGN(val, KB(4))