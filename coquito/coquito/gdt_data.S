.section .gdt
.global global_descriptor_table
.type global_descriptor_table, @object

.align 16
global_descriptor_table:
.fill 8*128, 1, 0x90
.size global_descriptor_table, . - global_descriptor_table
