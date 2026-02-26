#pragma once

typedef void (*int_hander__handler_t)(void*);

void int_handler__nop(void* iframe);

void int_handler__division_error(void* iframe);
void int_handler__debug(void* iframe);
void int_handler__bound_range_exceeded(void* iframe);
void int_handler__invalid_opcode(void* iframe);
void int_handler__device_not_available(void* iframe);
void int_handler__double_fault(void* iframe);
void int_handler__invalid_tss(void* iframe);
void int_handler__segment_not_present(void* iframe);
void int_handler__stack_segment_fault(void* iframe);
void int_handler__general_protection_fault(void* iframe);
void int_handler__page_fault(void* iframe);
void int_handler__x87_floating_point_exception(void* iframe);
void int_handler__x87_alignement_check(void* iframe);
void int_handler__machine_check(void* iframe);
void int_handler__simd_floating_point_exception(void* iframe);
void int_handler__virtualization_exception(void* iframe);
void int_handler__control_protection_exception(void* iframe);
void int_handler__hypervisor_injection_exception(void* iframe);
void int_handler__vmm_communication(void* iframe);
void int_handler__security_exception(void* iframe);