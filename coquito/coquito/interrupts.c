#include "interrupts.h"
#include "interrupt_handlers.h"
#include "segments.h"

static int_hander__handler_t interrupt_vectors[32] = {
    /** Vector #0 */
    int_handler__division_error,
    /** Vector #1 */
    int_handler__debug,
    int_handler__nop,
    int_handler__nop,
    int_handler__nop,
    /** Vector #5 */
    int_handler__bound_range_exceeded,
    /** Vector #6 */
    int_handler__invalid_opcode,
    /** Vector #7 */
    int_handler__device_not_available,
    /** Vector #8 */
    int_handler__double_fault,
    int_handler__nop,
    /** Vector #10 */
    int_handler__invalid_tss,
    /** Vector #11 */
    int_handler__segment_not_present,
    /** Vector #12 */
    int_handler__stack_segment_fault,
    /** Vector #13 */
    int_handler__general_protection_fault,
    /** Vector #14 */
    int_handler__page_fault,
    /** Vector #15 is reserved */
    int_handler__nop,
    /** Vector #16 */
    int_handler__x87_floating_point_exception,
    /** Vector #17 */
    int_handler__x87_alignement_check,
    /** Vector #18 */
    int_handler__machine_check,
    /** Vector #19 */
    int_handler__simd_floating_point_exception,
    /** Vector #20 */
    int_handler__virtualization_exception,
    /** Vector #21 */
    int_handler__control_protection_exception,
    /** Vectors 22 to 27 (inclusive) are reserved */
    int_handler__nop,
    int_handler__nop,
    int_handler__nop,
    int_handler__nop,
    int_handler__nop,
    int_handler__nop,

    /** Vector #28 */
    int_handler__hypervisor_injection_exception,
    /** Vector #29 */
    int_handler__vmm_communication,
    /** Vector #30 */
    int_handler__security_exception,
    int_handler__nop
};

int_hander__handler_t interrupts__get_handler_for_exception(u8 exception){
    if(exception > 31){
        return int_handler__nop;
    } else {
        return interrupt_vectors[exception];
    }
}

void interrupts__fill_descriptor(interrupts__descriptor_t* descriptor, int_hander__handler_t isr, enum GDT_SEGMENTS segment, u8 ist, u8 type_attrs){
    descriptor->_zero = 0;

    // This ISR address is already a virtual
    // Make it a numerical type from a pointer
    // makes it simpler to cut in chunks 
    virtaddr_t isr_virt = (virtaddr_t)(isr);

    descriptor->offset_1 = (u16)((isr_virt>>00)&0xffff);
    descriptor->offset_2 = (u16)((isr_virt>>16)&0xffff);
    descriptor->offset_3 = (u32)((isr_virt>>32)&0xffffffff);

    descriptor->ist = ist & 0b111;   // sanitize IST

    // XXX We can't tell the C code to have enum GDT_SEGMENTS be defined
    // over u16 values.
    // This could be fixed if we were using C++...
    descriptor->selector = (u16)segment;
    descriptor->type_attrs = type_attrs;
}

void interrupts__load_idtr(interrupts__idtr_t* idtr){
    __asm__ volatile ("lidt %0" : : "m"(*idtr)); // load the new IDT
}

