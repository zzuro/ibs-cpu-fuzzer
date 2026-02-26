.section .resetvector
.code16

.intel_syntax noprefix

.global reset_vector_entry
.type reset_vector_entry, @function


reset_vector_entry:

mov     eax, cr0
test    al, 1
jz     after_loop

/* jmp bootstrap_main */

cli
loop:
    hlt
    jmp loop
after_loop:

.size reset_vector_entry, . - reset_vector_entry

