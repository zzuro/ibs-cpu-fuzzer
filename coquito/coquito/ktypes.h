#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

typedef u64 physaddr_t;
typedef u64 virtaddr_t;

inline void fault(void){
    __asm__ volatile ("ud2");
}

inline void debug(void){
    __asm__ volatile ("int3");
}

#define FORCED_INLINE inline __attribute__((always_inline))