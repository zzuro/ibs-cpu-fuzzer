#pragma once

#include "ktypes.h"
#include "sevsnp.h"

static inline void nop(void){
    __asm__ volatile( "nop" :::);
} 

static inline void outb(u16 port, u16 val) {
    /* See https://wiki.osdev.org/Inline_Assembly/Examples#OUTx */
    __asm__ volatile ( "outb %b0, %w1" : : "a"(val), "Nd"(port) : "memory");
}

static inline u8 inb(u16 port) {
    /* See https://wiki.osdev.org/Inline_Assembly/Examples#INx */
    u8 ret;  // so that is_transmit_empty always succeeds.
    __asm__ volatile ( "inb %w1, %b0"
                   : "=a"(ret)
                   : "Nd"(port)
                   : "memory");
    return ret;
}

static inline void insl(u16 port, void *addr, u32 count) {
    __asm__ volatile (
        "mov %0, %%dx\n\t"
        "mov %1, %%rdi\n\t"
        "mov %2, %%ecx\n\t"
        "REP insl"
        :
        : "r"(port), "r"(addr), "r"(count)
        : "dx", "rdi", "ecx", "memory"
    );
}