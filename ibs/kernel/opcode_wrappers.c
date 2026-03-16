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
{                                                                              \
    int rc;                                                                    \
    int vec;                                                                   \
    u64 rip;                                                                   \
                                                                               \
    (void)arg0;                                                                \
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
        :                                                                      \
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
    u16 port = (u16)arg0;                                                     \
                                                                             \
    asm volatile(                                                             \
        "mov %[buf], %%rdi\n\t"                                               \
        "mov %[port], %%dx\n\t"                                               \
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
        : "rax","rdx","rdi","memory","cc");                                   \
                                                                             \
    if (out) {                                                                \
        out->rc = rc;                                                         \
        out->vec = vec;                                                       \
        out->rip = rip;                                                       \
    }                                                                         \
    return rc;                                                                \
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
    {}
};


DEFINE_OPCODE_WRAPPER0(try_nop,   "nop")
DEFINE_OPCODE_WRAPPER0(try_pause, "pause")
DEFINE_OPCODE_WRAPPER_EAX_ECX(try_cpuid, "cpuid")
DEFINE_OPCODE_WRAPPER0(try_ud2,   "ud2")

DEFINE_OPCODE_WRAPPER0(try_in_imm_e4, ".byte 0xe4, 0x80")   /* IN AL,0x80 */
DEFINE_OPCODE_WRAPPER0(try_in_imm_e5, ".byte 0xe5, 0x80")   /* IN EAX,0x80 */

DEFINE_OPCODE_WRAPPER0(try_out_imm_e6, ".byte 0xe6, 0x80")  /* OUT 0x80,AL */
DEFINE_OPCODE_WRAPPER0(try_out_imm_e7, ".byte 0xe7, 0x80")  /* OUT 0x80,EAX */

DEFINE_OPCODE_WRAPPER_DX(try_in_dx_ec, "in %%dx, %%al")
DEFINE_OPCODE_WRAPPER_DX(try_in_dx_ed, "in %%dx, %%eax")

DEFINE_OPCODE_WRAPPER_DX(try_out_dx_ee, "out %%al, %%dx")
DEFINE_OPCODE_WRAPPER_DX(try_out_dx_ef, "out %%eax, %%dx")

DEFINE_OPCODE_WRAPPER_IOSTRING(try_insb,  "insb")
DEFINE_OPCODE_WRAPPER_IOSTRING(try_insd,  "insl")
DEFINE_OPCODE_WRAPPER_IOSTRING(try_outsb, "outsb")
DEFINE_OPCODE_WRAPPER_IOSTRING(try_outsd, "outsl")


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
    default:
        if (out) {
            out->rc = -1;
            out->vec = -1;
            out->rip = 0;
        }
        return -1;
    }
}