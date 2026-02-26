#pragma once

#include "ktypes.h"
#include "interrupt_handlers.h"
#include "segments.h"

#define N_IDT_ENTRIES_MAX 256
#define N_EXCEPTION_VECTORS 32

struct __attribute__((packed)) interrupts__descriptor { 
    u16 offset_1;
    u16 selector;
    u8 ist;
    u8 type_attrs;
    u16 offset_2;
    u32 offset_3;
    u32 _zero;  
};
typedef struct interrupts__descriptor interrupts__descriptor_t;

struct __attribute__((packed)) interrupts__idtr {
    u16 size;
    interrupts__descriptor_t* offset;
};
typedef struct interrupts__idtr interrupts__idtr_t ;

int_hander__handler_t interrupts__get_handler_for_exception(u8 exception);

void interrupts__fill_descriptor(interrupts__descriptor_t* descriptor, int_hander__handler_t isr, enum GDT_SEGMENTS segment, u8 ist, u8 type_attrs);

void interrupts__load_idtr(interrupts__idtr_t* idtr);

FORCED_INLINE static void interrupts__sti(void){
    // set the interrupt flag
    __asm__ volatile ("sti");
}

FORCED_INLINE static void interrupts__cli(void){
    // set the interrupt flag
    __asm__ volatile ("cli");
}