#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/extable.h>

#include "opcode_wrappers.h"

#define OPENTRY(_id, _en, _a0, _a1) \
    { .id = (_id), .name = #_id, .enabled = (_en), .needs_arg0 = (_a0), .needs_arg1 = (_a1) }

/*
 * Wrapper for instructions with no input operands.
 *
 * The instruction is emitted at label 1 so extable can recover from faults.
 * vec gets EAX on fault-path, matching your existing pattern.
 * rip_out receives the RIP of the instruction site.
 */
#define DEFINE_OPCODE_WRAPPER0(fn_name, insn_asm, clobbers...)                \
int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)                    \
{                                                                            \
    int rc;                                                                  \
    int vec;                                                                 \
    u64 rip;                                                                 \
                                                                             \
    (void)arg0;                                                              \
    (void)arg1;                                                              \
                                                                             \
    asm volatile(                                                            \
        "movl $0, %[rc]\n\t"                                                 \
        "movl $1, %%ecx\n\t"                                                 \
        "movl $-1, %[vec]\n\t"                                               \
        "leaq 1f(%%rip), %[rip]\n\t"                                         \
        "1: \n\t"                                   \
        insn_asm "\n\t"                                                      \
        "2:\n\t"                                                             \
        ".section .fixup,\"ax\"\n\t"                                         \
        "3:\n\t"                                                             \
        "movl %%eax, %[vec]\n\t"                                             \
        "movl $-1, %[rc]\n\t"                                                \
        "jmp 2b\n\t"                                                         \
        ".previous\n\t"                                                      \
        _ASM_EXTABLE_FAULT(1b, 3b)                                           \
        : [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip)                 \
        :                                                                    \
        : "rax", "ecx", "cc", "memory", ##clobbers);                         \
                                                                             \
    if (out) {                                                               \
        out->rc = rc;                                                        \
        out->vec = vec;                                                      \
        out->rip = rip;                                                      \
    }                                                                        \
                                                                             \
    return rc;                                                               \
}

/*
 * Wrapper for instructions that need arg0 in RAX.
 */
#define DEFINE_OPCODE_WRAPPER_RAX(fn_name, insn_asm, clobbers...)             \
int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)                    \
{                                                                             \
    int rc;                                                                   \
    int vec;                                                                  \
    u64 rip;                                                                  \
                                                                             \
    (void)arg1;                                                               \
                                                                             \
    asm volatile(                                                             \
        "movl $0, %[rc]\n\t"                                                  \
        "movl $-1, %[vec]\n\t"                                                \
        "mov %[arg0], %%rax\n\t"                                              \
        "leaq 1f(%%rip), %[rip]\n\t"                                          \
        "1: " insn_asm "\n\t"                                                 \
        "2:\n\t"                                                              \
        ".section .fixup,\"ax\"\n\t"                                          \
        "3:\n\t"                                                              \
        "movl %%eax, %[vec]\n\t"                                              \
        "movl $-1, %[rc]\n\t"                                                 \
        "jmp 2b\n\t"                                                          \
        ".previous\n\t"                                                       \
        _ASM_EXTABLE_FAULT(1b, 3b)                                            \
        : [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip)                  \
        : [arg0] "r"(arg0)                                                    \
        : "rax", "cc", "memory", ##clobbers);                                 \
                                                                             \
    if (out) {                                                                \
        out->rc = rc;                                                         \
        out->vec = vec;                                                       \
        out->rip = rip;                                                       \
    }                                                                         \
                                                                             \
    return rc;                                                                \
}

/*
 * Wrapper for instructions that need arg0 in RAX and arg1 in RCX.
 */
#define DEFINE_OPCODE_WRAPPER_RAX_RCX(fn_name, insn_asm, clobbers...)         \
int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)                    \
{                                                                             \
    int rc;                                                                   \
    int vec;                                                                  \
    u64 rip;                                                                  \
                                                                             \
    asm volatile(                                                             \
        "movl $0, %[rc]\n\t"                                                  \
        "movl $-1, %[vec]\n\t"                                                \
        "mov %[arg0], %%rax\n\t"                                              \
        "mov %[arg1], %%rcx\n\t"                                              \
        "leaq 1f(%%rip), %[rip]\n\t"                                          \
        "1: " insn_asm "\n\t"                                                 \
        "2:\n\t"                                                              \
        ".section .fixup,\"ax\"\n\t"                                          \
        "3:\n\t"                                                              \
        "movl %%eax, %[vec]\n\t"                                              \
        "movl $-1, %[rc]\n\t"                                                 \
        "jmp 2b\n\t"                                                          \
        ".previous\n\t"                                                       \
        _ASM_EXTABLE_FAULT(1b, 3b)                                            \
        : [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip)                  \
        : [arg0] "r"(arg0), [arg1] "r"(arg1)                                  \
        : "rax", "rcx", "cc", "memory", ##clobbers);                          \
                                                                             \
    if (out) {                                                                \
        out->rc = rc;                                                         \
        out->vec = vec;                                                       \
        out->rip = rip;                                                       \
    }                                                                         \
                                                                             \
    return rc;                                                                \
}

/*
 * Wrapper for instructions that need arg0 in EAX, arg1 in ECX.
 * Useful for benign test patterns where the low 32 bits matter.
 */
#define DEFINE_OPCODE_WRAPPER_EAX_ECX(fn_name, insn_asm, clobbers...)         \
int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)                    \
{                                                                             \
    int rc;                                                                   \
    int vec;                                                                  \
    u64 rip;                                                                  \
    u32 a0 = (u32)arg0;                                                       \
    u32 a1 = (u32)arg1;                                                       \
                                                                             \
    asm volatile(                                                             \
        "movl $0, %[rc]\n\t"                                                  \
        "movl $-1, %[vec]\n\t"                                                \
        "mov %[arg0], %%eax\n\t"                                              \
        "mov %[arg1], %%ecx\n\t"                                              \
        "leaq 1f(%%rip), %[rip]\n\t"                                          \
        "1: " insn_asm "\n\t"                                                 \
        "2:\n\t"                                                              \
        ".section .fixup,\"ax\"\n\t"                                          \
        "3:\n\t"                                                              \
        "movl %%eax, %[vec]\n\t"                                              \
        "movl $-1, %[rc]\n\t"                                                 \
        "jmp 2b\n\t"                                                          \
        ".previous\n\t"                                                       \
        _ASM_EXTABLE_FAULT(1b, 3b)                                            \
        : [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip)                  \
        : [arg0] "r"(a0), [arg1] "r"(a1)                                      \
        : "rax", "rcx", "rbx", "rdx", "cc", "memory", ##clobbers);            \
                                                                             \
    if (out) {                                                                \
        out->rc = rc;                                                         \
        out->vec = vec;                                                       \
        out->rip = rip;                                                       \
    }                                                                         \
                                                                             \
    return rc;                                                                \
}

/*
 * Wrapper for instructions that use DX as port register
 */
#define DEFINE_OPCODE_WRAPPER_DX(fn_name, insn_asm, clobbers...)             \
int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)                    \
{                                                                             \
    int rc;                                                                   \
    int vec;                                                                  \
    u64 rip;                                                                  \
    u16 port = (u16)arg0;                                                     \
                                                                             \
    asm volatile(                                                             \
        "movl $0, %[rc]\n\t"                                                  \
        "movl $-1, %[vec]\n\t"                                                \
        "mov %[port], %%dx\n\t"                                               \
        "leaq 1f(%%rip), %[rip]\n\t"                                          \
        "1: " insn_asm "\n\t"                                                 \
        "2:\n\t"                                                              \
        ".section .fixup,\"ax\"\n\t"                                          \
        "3:\n\t"                                                              \
        "movl %%eax, %[vec]\n\t"                                              \
        "movl $-1, %[rc]\n\t"                                                 \
        "jmp 2b\n\t"                                                          \
        ".previous\n\t"                                                       \
        _ASM_EXTABLE_FAULT(1b, 3b)                                            \
        : [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip)                  \
        : [port] "r"(port)                                                    \
        : "rax","rdx","cc","memory", ##clobbers);                             \
                                                                             \
    if (out) {                                                                \
        out->rc = rc;                                                         \
        out->vec = vec;                                                       \
        out->rip = rip;                                                       \
    }                                                                         \
    return rc;                                                                \
}

#define DEFINE_OPCODE_WRAPPER_IOSTRING(fn_name, insn_asm)                     \
int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)                    \
{                                                                             \
    int rc;                                                                   \
    int vec;                                                                  \
    u64 rip;                                                                  \
    void *buf = (void*)arg1;                                                  \
    u32 port = (u32)arg0;                                                     \
                                                                             \
    asm volatile(                                                             \
        "mov %[buf], %%rdi\n\t"                                               \
        "mov %[port], %%edx\n\t"                                               \
        "movl $5, %%ecx\n\t"                                               \
        "movl $0, %[rc]\n\t"                                                  \
        "movl $-1, %[vec]\n\t"                                                \
        "leaq 1f(%%rip), %[rip]\n\t"                                          \
        "1: " insn_asm "\n\t"                                                 \
        "2:\n\t"                                                              \
        ".section .fixup,\"ax\"\n\t"                                          \
        "3:\n\t"                                                              \
        "movl %%eax, %[vec]\n\t"                                              \
        "movl $-1, %[rc]\n\t"                                                 \
        "jmp 2b\n\t"                                                          \
        ".previous\n\t"                                                       \
        _ASM_EXTABLE_FAULT(1b, 3b)                                            \
        : [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip)                  \
        : [port] "r"(port), [buf] "r"(buf)                                    \
        : "rax","edx","rdi", "ecx", "memory","cc");                                   \
                                                                             \
    if (out) {                                                                \
        out->rc = rc;                                                         \
        out->vec = vec;                                                       \
        out->rip = rip;                                                       \
    }                                                                         \
    return rc;                                                                \
}

/*
 * EDX:EAX result producer, no input args.
 */
#define DEFINE_OPCODE_WRAPPER_EDX_EAX_OUT0(fn_name, insn_asm, clobbers...)    \
int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)                    \
{                                                                              \
    int rc;                                                                    \
    int vec;                                                                   \
    u64 rip;                                                                   \
    u32 lo = 0, hi = 0;                                                        \
                                                                               \
    (void)arg0;                                                                \
    (void)arg1;                                                                \
                                                                               \
    asm volatile(                                                              \
        "movl $0, %[rc]\n\t"                                                   \
        "movl $-1, %[vec]\n\t"                                                 \
        "leaq 1f(%%rip), %[rip]\n\t"                                           \
        "1: " insn_asm "\n\t"                                                  \
        "movl %%eax, %[lo]\n\t"                                                \
        "movl %%edx, %[hi]\n\t"                                                \
        "2:\n\t"                                                               \
        ".section .fixup,\"ax\"\n\t"                                           \
        "3:\n\t"                                                               \
        "movl %%eax, %[vec]\n\t"                                               \
        "movl $-1, %[rc]\n\t"                                                  \
        "jmp 2b\n\t"                                                           \
        ".previous\n\t"                                                        \
        _ASM_EXTABLE_FAULT(1b, 3b)                                             \
        : [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip),                  \
          [lo] "=&r"(lo), [hi] "=&r"(hi)                                       \
        :                                                                      \
        : "rax", "rdx", "cc", "memory", ##clobbers);                           \
                                                                               \
    if (out) {                                                                 \
        out->rc = rc;                                                          \
        out->vec = vec;                                                        \
        out->rip = rip;                                                        \
    }                                                                          \
                                                                               \
    return rc;                                                                 \
}

/*
 * ECX input, EDX:EAX output. Useful for RDPMC.
 */
#define DEFINE_OPCODE_WRAPPER_ECX_EDX_EAX_OUT(fn_name, insn_asm, clobbers...)  \
int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)                     \
{                                                                               \
    int rc;                                                                     \
    int vec;                                                                    \
    u64 rip;                                                                    \
    u32 ecx_in = (u32)arg0;                                                     \
    u32 lo = 0, hi = 0;                                                         \
                                                                                \
    (void)arg1;                                                                 \
                                                                                \
    asm volatile(                                                               \
        "movl $0, %[rc]\n\t"                                                    \
        "movl $-1, %[vec]\n\t"                                                  \
        "mov %[ecx_in], %%ecx\n\t"                                              \
        "leaq 1f(%%rip), %[rip]\n\t"                                            \
        "1: " insn_asm "\n\t"                                                   \
        "movl %%eax, %[lo]\n\t"                                                 \
        "movl %%edx, %[hi]\n\t"                                                 \
        "2:\n\t"                                                                \
        ".section .fixup,\"ax\"\n\t"                                            \
        "3:\n\t"                                                                \
        "movl %%eax, %[vec]\n\t"                                                \
        "movl $-1, %[rc]\n\t"                                                   \
        "jmp 2b\n\t"                                                            \
        ".previous\n\t"                                                         \
        _ASM_EXTABLE_FAULT(1b, 3b)                                              \
        : [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip),                   \
          [lo] "=&r"(lo), [hi] "=&r"(hi)                                        \
        : [ecx_in] "r"(ecx_in)                                                  \
        : "rax", "rcx", "rdx", "cc", "memory", ##clobbers);                     \
                                                                                \
    if (out) {                                                                  \
        out->rc = rc;                                                           \
        out->vec = vec;                                                         \
        out->rip = rip;                                                         \
    }                                                                           \
                                                                                \
    return rc;                                                                  \
}

/*
 * One pointer argument, used as a memory operand. Useful for CLFLUSH.
 * arg0 = address
 */
#define DEFINE_OPCODE_WRAPPER_MEMARG0(fn_name, insn_asm, clobbers...)          \
int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)                     \
{                                                                              \
    int rc;                                                                    \
    int vec;                                                                   \
    u64 rip;                                                                   \
    void *p = (void *)arg0;                                                    \
                                                                               \
    (void)arg1;                                                                \
                                                                               \
    asm volatile(                                                              \
        "movl $0, %[rc]\n\t"                                                   \
        "movl $-1, %[vec]\n\t"                                                 \
        "leaq 1f(%%rip), %[rip]\n\t"                                           \
        "1: " insn_asm "\n\t"                                                  \
        "2:\n\t"                                                               \
        ".section .fixup,\"ax\"\n\t"                                           \
        "3:\n\t"                                                               \
        "movl %%eax, %[vec]\n\t"                                               \
        "movl $-1, %[rc]\n\t"                                                  \
        "jmp 2b\n\t"                                                           \
        ".previous\n\t"                                                        \
        _ASM_EXTABLE_FAULT(1b, 3b)                                             \
        : [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip)                   \
        : [mem] "m" (*(char *)p)                                               \
        : "rax", "cc", "memory", ##clobbers);                                  \
                                                                               \
    if (out) {                                                                 \
        out->rc = rc;                                                          \
        out->vec = vec;                                                        \
        out->rip = rip;                                                        \
    }                                                                          \
                                                                               \
    return rc;                                                                 \
}

#define DEFINE_OPCODE_WRAPPER_WRMSR(fn_name)                                   \
int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)                     \
{                                                                              \
    int rc;                                                                    \
    int vec;                                                                   \
    u64 rip;                                                                   \
    u32 msr = (u32)arg0;                                                       \
    u32 low = (u32)arg1;                                                       \
    u32 high = (u32)(arg1 >> 32);                                              \
                                                                               \
    asm volatile(                                                              \
        "movl $0, %[rc]\n\t"                                                   \
        "movl $-1, %[vec]\n\t"                                                 \
        "leaq 1f(%%rip), %[rip]\n\t"                                           \
        "1: wrmsr\n\t"                                                         \
        "2:\n\t"                                                               \
        ".section .fixup,\"ax\"\n\t"                                           \
        "3:\n\t"                                                               \
        "movl %%eax, %[vec]\n\t"                                               \
        "movl $-1, %[rc]\n\t"                                                  \
        "jmp 2b\n\t"                                                           \
        ".previous\n\t"                                                        \
        _ASM_EXTABLE_FAULT(1b, 3b)                                             \
        : [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip)                   \
        : "c"(msr), "a"(low), "d"(high)                                        \
        : "cc", "memory");                                                     \
                                                                               \
    if (out) {                                                                 \
        out->rc = rc;                                                          \
        out->vec = vec;                                                        \
        out->rip = rip;                                                        \
    }                                                                          \
                                                                               \
    return rc;                                                                 \
}

#define DEFINE_OPCODE_WRAPPER_RDMSR(fn_name)                                   \
int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)                     \
{                                                                              \
    int rc;                                                                    \
    int vec;                                                                   \
    u64 rip;                                                                   \
    u32 ecx_out = 0;                                                           \
                                                                               \
    (void)arg0;                                                                \
    (void)arg1;                                                                \
                                                                               \
    asm volatile(                                                              \
        "movl $0, %[rc]\n\t"                                                   \
        "movl $-1, %[vec]\n\t"                                                 \
        "leaq 1f(%%rip), %[rip]\n\t"                                           \
        "movl $0xc0011033, %%ecx\n\t"                                          \
        "1:\n\t"                                                               \
        ".byte 0xf3, 0xf3, 0x0f, 0x32\n\t"                                           \
        "movl %%ecx, %[ecx_out]\n\t"                                           \
        "2:\n\t"                                                               \
        ".section .fixup,\"ax\"\n\t"                                           \
        "3:\n\t"                                                               \
        "movl %%eax, %[vec]\n\t"                                               \
        "movl %%ecx, %[ecx_out]\n\t"                                           \
        "movl $-1, %[rc]\n\t"                                                  \
        "jmp 2b\n\t"                                                           \
        ".previous\n\t"                                                        \
        _ASM_EXTABLE_FAULT(1b, 3b)                                             \
        : [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip),                  \
          [ecx_out] "=&r"(ecx_out)                                             \
        :                                                                      \
        : "rax", "rcx", "rdx", "cc", "memory");                                \
                                                                               \
                                                                               \
    if (out) {                                                                 \
        out->rc = rc;                                                          \
        out->vec = vec;                                                        \
        out->rip = rip;                                                        \
    }                                                                          \
                                                                               \
    return rc;                                                                 \
}

#define DEFINE_OPCODE_WRAPPER_REP_MOVSQ(fn_name, clobbers...)                     \
int fn_name(u64 src, u64 dst, u64 count, struct opcode_result *out)              \
{                                                                                 \
    int rc;                                                                       \
    int vec;                                                                      \
    u64 rip;                                                                      \
                                                                                  \
    asm volatile(                                                                 \
        "movl $0, %[rc]\n\t"                                                      \
        "movl $-1, %[vec]\n\t"                                                    \
        "mov %[src], %%rsi\n\t"                                                   \
        "mov %[dst], %%rdi\n\t"                                                   \
        "mov %[count], %%rcx\n\t"                                                 \
        "leaq 1f(%%rip), %[rip]\n\t"                                              \
        "1: rex.rxb rep movsq\n\t"                                                        \
        "2:\n\t"                                                                  \
        ".section .fixup,\"ax\"\n\t"                                              \
        "3:\n\t"                                                                  \
        "movl %%eax, %[vec]\n\t"                                                  \
        "movl $-1, %[rc]\n\t"                                                     \
        "jmp 2b\n\t"                                                              \
        ".previous\n\t"                                                           \
        _ASM_EXTABLE_FAULT(1b, 3b)                                                \
        : [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip)                      \
        : [src] "r"(src), [dst] "r"(dst), [count] "r"(count)                     \
        : "rax", "rcx", "rsi", "rdi", "cc", "memory", ##clobbers);               \
                                                                                  \
    if (out) {                                                                    \
        out->rc = rc;                                                             \
        out->vec = vec;                                                           \
        out->rip = rip;                                                           \
    }                                                                             \
                                                                                  \
    return rc;                                                                    \
}

#define DEFINE_OPCODE_WRAPPER_RMPUPDATE(fn_name, clobbers...)                    \
int fn_name(u64 spa, u64 val, struct opcode_result *out)                         \
{                                                                                \
	int rc;                                                                  \
	int vec;                                                                 \
	u64 rip;                                                                 \
	u32 eax_out;                                                             \
	                                                                             \
	asm volatile(                                                            \
		"movl $0, %[rc]\n\t"                                             \
		"movl $-1, %[vec]\n\t"                                           \
		"mov %[spa], %%rax\n\t"                                          \
		"mov %[val], %%rcx\n\t"                                          \
		"leaq 1f(%%rip), %[rip]\n\t"                                     \
		"1: rmpupdate %%rax, %%rcx\n\t"                                  \
		"movl %%eax, %[eax_out]\n\t"                                     \
		"2:\n\t"                                                         \
		".section .fixup,\"ax\"\n\t"                                     \
		"3:\n\t"                                                         \
		"movl %%eax, %[vec]\n\t"                                         \
		"movl $-1, %[rc]\n\t"                                            \
		"jmp 2b\n\t"                                                     \
		".previous\n\t"                                                  \
		_ASM_EXTABLE_FAULT(1b, 3b)                                       \
		: [rc] "=&r"(rc),                                                \
		  [vec] "=&r"(vec),                                              \
		  [rip] "=&r"(rip),                                              \
		  [eax_out] "=&r"(eax_out)                                       \
		: [spa] "r"(spa), [val] "r"(val)                                 \
		: "rax", "rcx", "cc", "memory", ##clobbers);                     \
	                                                                             \
	if (out) {                                                             \
		out->rc = rc;                                                  \
		out->vec = (rc == 0) ? (int)eax_out : vec;                     \
		out->rip = rip;                                                \
	}                                                                        \
	                                                                             \
	return rc;                                                               \
}

#define DEFINE_OPCODE_WRAPPER_ECX_EDX_EAX_OUT0(fn_name, insn_asm, clobbers...) \
int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)                      \
{                                                                                \
    int rc;                                                                      \
    int vec;                                                                     \
    u64 rip;                                                                     \
    u32 aux = 0, lo = 0, hi = 0;                                                 \
                                                                                 \
    (void)arg0;                                                                  \
    (void)arg1;                                                                  \
                                                                                 \
    asm volatile(                                                                \
        "movl $0, %[rc]\n\t"                                                     \
        "movl $-1, %[vec]\n\t"                                                   \
        "leaq 1f(%%rip), %[rip]\n\t"                                             \
        "1: " insn_asm "\n\t"                                                    \
        "movl %%ecx, %[aux]\n\t"                                                 \
        "movl %%eax, %[lo]\n\t"                                                  \
        "movl %%edx, %[hi]\n\t"                                                  \
        "2:\n\t"                                                                 \
        ".section .fixup,\"ax\"\n\t"                                             \
        "3:\n\t"                                                                 \
        "movl %%eax, %[vec]\n\t"                                                 \
        "movl $-1, %[rc]\n\t"                                                    \
        "jmp 2b\n\t"                                                             \
        ".previous\n\t"                                                          \
        _ASM_EXTABLE_FAULT(1b, 3b)                                               \
        : [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip),                    \
          [aux] "=&r"(aux), [lo] "=&r"(lo), [hi] "=&r"(hi)                       \
        :                                                                        \
        : "rax", "rcx", "rdx", "cc", "memory", ##clobbers);                      \
                                                                                 \
    if (out) {                                                                   \
        out->rc = rc;                                                            \
        out->vec = vec;                                                          \
        out->rip = rip;                                                          \
        /* store aux/lo/hi somewhere too if your struct supports it */           \
    }                                                                            \
                                                                                 \
    return rc;                                                                   \
}

struct opcode_desc opcode_table[] = {
    OPENTRY(OP_NOP,   true,  false, false),
    OPENTRY(OP_PAUSE, true,  false, false),
    OPENTRY(OP_CPUID, true,  true,  true),
    OPENTRY(OP_UD2,   true,  false, false),
    OPENTRY(OP_IN_IMM_AL, true, false, false),
    OPENTRY(OP_IN_IMM_EAX, true, false, false),
    OPENTRY(OP_IN_DX_AL, true, false, false),
    OPENTRY(OP_IN_DX_EAX, true, false, false),
    OPENTRY(OP_OUT_IMM_AL, true, false, false),
    OPENTRY(OP_OUT_IMM_EAX, true, false, false),
    OPENTRY(OP_OUT_DX_AL, true, false, false),
    OPENTRY(OP_OUT_DX_EAX, true, false, false),
    OPENTRY(OP_INSB, true, false, false),
    OPENTRY(OP_INSD, true, false, false),
    OPENTRY(OP_OUTSB, true, false, false),
    OPENTRY(OP_OUTSD, true, false, false),
    OPENTRY(OP_RDTSC, true, false, false),
    OPENTRY(OP_RDPMC, true, true, false),
    OPENTRY(OP_CLFLUSH, true, true, false),
    OPENTRY(OP_WRMSR, true, true, true),
    OPENTRY(OP_VMSAVE, true, true, false),
    OPENTRY(OP_MOVSQ, true, true, true),
    OPENTRY(OP_SIDT, true, true, false),
    OPENTRY(OP_SGDT, true, true, false),
    OPENTRY(OP_WBINVD, true, false, false),
    OPENTRY(OP_CLWB, true, true, false),
    OPENTRY(OP_INVLPG, true, true, false),
    OPENTRY(OP_MONITOR, true, true, false),
    OPENTRY(OP_UDBGRD, true, true, false),
    OPENTRY(OP_RMPUPDATE, true, true, true),
    OPENTRY(OP_LFENCE, true, false, false),
    OPENTRY(OP_RDTSCP, true, false, false),
    OPENTRY(OP_PREFETCHW, true, true, false),
    OPENTRY(OP_PREFETCHWT1, true, true, false),
    OPENTRY(OP_READ_CR0, true, false, false),
    OPENTRY(OP_READ_CR2, true, false, false),
    OPENTRY(OP_READ_CR3, true, false, false),
    OPENTRY(OP_READ_CR4, true, false, false),
    OPENTRY(OP_RDMSR, true, true, false),
    {}
};


DEFINE_OPCODE_WRAPPER0(try_nop,   "nop")
DEFINE_OPCODE_WRAPPER0(try_wbinvd,   "wbinvd")   
DEFINE_OPCODE_WRAPPER0(try_pause, "pause")
DEFINE_OPCODE_WRAPPER_EAX_ECX(try_cpuid, "cpuid")
DEFINE_OPCODE_WRAPPER0(try_ud2,   "ud2")


DEFINE_OPCODE_WRAPPER0(try_in_imm_e4, ".byte 0xe4, 0x88")   
DEFINE_OPCODE_WRAPPER0(try_in_imm_e5, ".byte 0xe5, 0x80")   

DEFINE_OPCODE_WRAPPER0(try_out_imm_e6, ".byte 0xe6, 0x80")  
DEFINE_OPCODE_WRAPPER0(try_out_imm_e7, ".byte 0xe7, 0x80")  

DEFINE_OPCODE_WRAPPER_DX(try_in_dx_ec, "in %%dx, %%al")
DEFINE_OPCODE_WRAPPER_DX(try_in_dx_ed, "in %%dx, %%eax")

DEFINE_OPCODE_WRAPPER_DX(try_out_dx_ee, "out %%al, %%dx")
DEFINE_OPCODE_WRAPPER_DX(try_out_dx_ef, "out %%ax, %%dx")

DEFINE_OPCODE_WRAPPER_IOSTRING(try_insb,  "REP insb")
DEFINE_OPCODE_WRAPPER_IOSTRING(try_insd,  "REP insl")
DEFINE_OPCODE_WRAPPER_IOSTRING(try_outsb, "outsb")
DEFINE_OPCODE_WRAPPER_IOSTRING(try_outsd, "REP outsl")

DEFINE_OPCODE_WRAPPER_EDX_EAX_OUT0(try_rdtsc, "rdtsc")
DEFINE_OPCODE_WRAPPER_ECX_EDX_EAX_OUT(try_rdpmc, "rdpmc")
DEFINE_OPCODE_WRAPPER_MEMARG0(try_clflushopt, "clflushopt %[mem]")
DEFINE_OPCODE_WRAPPER_MEMARG0(try_clwb, "clwb %[mem]")
DEFINE_OPCODE_WRAPPER_MEMARG0(try_invlpg, "invlpg %[mem]")

DEFINE_OPCODE_WRAPPER_WRMSR(do_wrmsr);

DEFINE_OPCODE_WRAPPER_RAX(try_vmsave, ".byte 0x0f, 0x01, 0xdb")
DEFINE_OPCODE_WRAPPER_REP_MOVSQ(test_rep_movsq);

DEFINE_OPCODE_WRAPPER_MEMARG0(try_sidt, "sidt %[mem]")
DEFINE_OPCODE_WRAPPER_MEMARG0(try_sgdt, "sgdt %[mem]")

DEFINE_OPCODE_WRAPPER_RAX(try_monitor, "monitor")

DEFINE_OPCODE_WRAPPER_RAX_RCX(try_udbgrd, ".byte 0x0f, 0x0e")
DEFINE_OPCODE_WRAPPER_RMPUPDATE(test_rmpupdate)

DEFINE_OPCODE_WRAPPER_ECX_EDX_EAX_OUT0(try_rdtscp, "rdtscp")
DEFINE_OPCODE_WRAPPER0(try_lfence, "lfence")

DEFINE_OPCODE_WRAPPER_MEMARG0(try_prefetchw,   "prefetchw %[mem]")
DEFINE_OPCODE_WRAPPER_MEMARG0(try_prefetchwt1, "prefetchwt1 %[mem]")

DEFINE_OPCODE_WRAPPER0(try_read_cr0, "mov %%cr0, %%rax")
DEFINE_OPCODE_WRAPPER0(try_read_cr2, "mov %%cr2, %%rax")
DEFINE_OPCODE_WRAPPER0(try_read_cr3, "mov %%cr3, %%rax")
DEFINE_OPCODE_WRAPPER0(try_read_cr4, "mov %%cr4, %%rax")

DEFINE_OPCODE_WRAPPER_RDMSR(try_rdmsr)


int run_selected_opcode(enum opcode_id id, u64 arg0, u64 arg1,
                        struct opcode_result *out)
{
    switch (id) {
    case OP_NOP:
        return try_nop(arg0, arg1, out);
    case OP_PAUSE:
        return try_pause(arg0, arg1, out);
    case OP_CPUID:
        return try_cpuid(arg0, arg1, out);
    case OP_UD2:
        return try_ud2(arg0, arg1, out);
    case OP_IN_IMM_AL:
        return try_in_imm_e4(arg0, arg1, out);
    case OP_IN_IMM_EAX:
        return try_in_imm_e5(arg0, arg1, out);
    case OP_OUT_IMM_AL:
        return try_out_imm_e6(arg0, arg1, out);
    case OP_OUT_IMM_EAX:
        return try_out_imm_e7(arg0, arg1, out);
    case OP_IN_DX_AL:
        return try_in_dx_ec(arg0, arg1, out);
    case OP_IN_DX_EAX:
        return try_in_dx_ed(arg0, arg1, out);
    case OP_OUT_DX_AL:
        return try_out_dx_ee(arg0, arg1, out);
    case OP_OUT_DX_EAX:
        return try_out_dx_ef(arg0, arg1, out);
    case OP_INSB:
        return try_insb(arg0, arg1, out);
    case OP_INSD:
        return try_insd(arg0, arg1, out);
    case OP_OUTSB:
        return try_outsb(arg0, arg1, out);
    case OP_OUTSD:
        return try_outsd(arg0, arg1, out);
    case OP_RDTSC:
        return try_rdtsc(arg0, arg1, out);
    case OP_RDPMC:
        return try_rdpmc(arg0, arg1, out);
    case OP_CLFLUSH:
        return try_clflushopt(arg0, arg1, out);
    case OP_WRMSR:
        return do_wrmsr(arg0, arg1, out);
    case OP_VMSAVE:
        return try_vmsave(arg0, arg1, out);
    case OP_MOVSQ:
        return test_rep_movsq(arg0, arg1, 5, out);
    case OP_SIDT:
        return try_sidt(arg0, arg1, out);
    case OP_SGDT:
        return try_sgdt(arg0, arg1, out);
    case OP_WBINVD:
        return try_wbinvd(arg0, arg1, out);
    case OP_CLWB:
        return try_clwb(arg0, arg1, out);
    case OP_INVLPG:
        return try_invlpg(arg0, arg1, out);
    case OP_MONITOR:
        return try_monitor(arg0, arg1, out);
    case OP_UDBGRD:
        return try_udbgrd(arg0, arg1, out);
    case OP_LFENCE:
        return try_lfence(arg0, arg1, out);
    case OP_RDTSCP:
        return try_rdtscp(arg0, arg1, out);
    case OP_PREFETCHW:
        return try_prefetchw(arg0, arg1, out);
    case OP_PREFETCHWT1:
        return try_prefetchwt1(arg0, arg1, out);
    case OP_READ_CR0:
        return try_read_cr0(arg0, arg1, out);
    case OP_READ_CR2:
        return try_read_cr2(arg0, arg1, out);
    case OP_READ_CR3:
        return try_read_cr3(arg0, arg1, out);
    case OP_READ_CR4:
        return try_read_cr4(arg0, arg1, out);
    case OP_RDMSR:
        return try_rdmsr(arg0, arg1, out);
    default:
        if (out) {
            out->rc = -1;
            out->vec = -1;
            out->rip = 0;
        }
        return -1;
    }
}