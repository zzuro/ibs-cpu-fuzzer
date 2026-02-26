.section .idt
.align 16
.global interrupt_descriptor_table
.type interrupt_descriptor_table, @object

.global interrupts_idtr
.type interrupts_idtr, @object
interrupts_idtr:
.align 16
.fill 16, 1, 0x91  /* way more than needed */

.align 16
interrupt_descriptor_table:
.fill 16*256, 1, 0x90
