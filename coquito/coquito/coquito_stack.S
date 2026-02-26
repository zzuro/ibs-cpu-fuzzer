.section .stack_kernel_c
.global coquito_stack
.type coquito_stack, @object

.align 16
stack_bottom:
.fill 4096*8, 1, 0x6c # 32 KiB 
stack_top:
coquito_stack:
