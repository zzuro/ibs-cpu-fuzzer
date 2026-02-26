/**
 * Taken from https://wiki.osdev.org/Bare_Bones
 * Licensed under Public Domain License, see https://wiki.osdev.org/OSDev_Wiki:License
 */

/* Declare constants for the multiboot header. */
.set ALIGN,    1<<0
.set MEMINFO,  1<<1
.set FLAGS,    ALIGN | MEMINFO
.set MAGIC,    0x1BADB002
.set CHECKSUM, -(MAGIC + FLAGS)

.section .multiboot
.align 4
.long MAGIC
.long FLAGS
.long CHECKSUM

/* set stack in a prevalidated region */
/* 4th prevalidate region, ranging from 0x900000 to 0x920000 (exclusive) */

.section .text
.global _start
.type _start, @function
.code64
_start:
    /* Set RSP to top of stack (stack grows down) */
    movabs $coquito_stack, %rsp
    and $-16, %rsp          /* 16-byte align */

    call kernel_main

    cli
1:  hlt
    jmp 1b
.size _start, . - _start