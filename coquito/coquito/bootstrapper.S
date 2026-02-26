/**
* Contains the necessary code to boostrap COQUITO
* Designed to be executed just after the VMPL swtich, in lieu of EDKII
* Based on the EDKII bootloader, found in the UefiCpuPkg/ResetVector/Vtf0 directory  
*
* This is not really a boot *loader*, as the code is actually already in memory.
* We just need to go from real mode to long mode.
*/

.include "gdt.S"

.intel_syntax noprefix

.section .bootstrap

.code32
.global bootstrap_main
.type bootstrap_main, @function
bootstrap_main:


/** Note: we assume that the A20 line has been disabled by QEMU */

/* Disable interrupts */
cli

/* Load GDT */
/* See https://wiki.osdev.org/GDT_Tutorial */
xor   EAX, EAX
mov   AX, DS
shl   EAX, 4
add   EAX, gdt_start 
jmp loop_forever
mov   [gdtr + 2], EAX
mov   EAX, gdt_end
sub   EAX, gdt_start
mov   [gdtr], AX


lgdt  [gdtr]

.code32

/* Reload segments */
jmp   0x08:gdt_setup_next_instr   /* 0x8: kernel mode code segment, see below */
gdt_setup_next_instr:
mov   AX, 0x10  /* kernel mode data segment, see below */
mov   DS, AX
mov   ES, AX
mov   FS, AX
mov   GS, AX
mov   SS, AX

loop_forever:
    hlt
    jmp loop_forever


gdtr:
.short 0  /* size */
.int 0    /* offset */


/* arguments to GDT_ENTRY macro: base, limit, access, flag */
gdt_start:
GDT_ENTRY 0x0, 0x0,    0x0,  0x0  /* NULL segment, index 0x0 */
GDT_ENTRY 0x0, 0xffff, 0x9a, 0x0  /* Kernel mode code segment, index 0x8 */
GDT_ENTRY 0x0, 0xffff, 0x92, 0xc  /* Kernel mode data segment, index 0x10 */

/* GDT_ENTRY 0x0, 0xffff, 0xfa, 0xc */
/* GDT_ENTRY 0x0, 0xffff, 0xf2, 0xc */
/* GDT_ENTRY 0x0, 0xffff, 0x89, 0x0 */
gdt_end:


.size bootstrap_main, . - bootstrap_main

