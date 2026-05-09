#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/extable.h>
#include <asm/fpu/api.h>
#include <asm/io.h>
#include <asm/sev.h>

#include "opcode_wrappers.h"


static __always_inline uint64_t measure_access_time(const uint8_t *addr)
{
    uint32_t lo_start, hi_start;
    uint32_t lo_end, hi_end;
    uint32_t aux;
    volatile uint8_t value;
    preempt_disable();
    /*
     * Serialize earlier memory ops before timing.
     * mfence is conservative; lfence is the key one for load timing.
     */
    asm volatile("mfence\n\t"
                 "lfence\n\t" ::: "memory");

    /* Read starting timestamp */
    asm volatile("rdtscp\n\t"
                 : "=a"(lo_start), "=d"(hi_start), "=c"(aux)
                 :
                 : "memory");

    /* Prevent later ops from executing early */
    asm volatile("lfence\n\t" ::: "memory");

    /* Timed load */
    asm volatile("movb (%1), %0\n\t"
                 : "=r"(value)
                 : "r"(addr)
                 : "memory");

    /* Ensure load completes before reading end timestamp */
    asm volatile("lfence\n\t" ::: "memory");

    /* Read ending timestamp */
    asm volatile("rdtscp\n\t"
                 : "=a"(lo_end), "=d"(hi_end), "=c"(aux)
                 :
                 : "memory");

    asm volatile("mfence\n\t" ::: "memory");
    preempt_enable();
    return (((uint64_t)hi_end << 32) | lo_end) -
           (((uint64_t)hi_start << 32) | lo_start);
}



#define OPENTRY(_id, _enabled, _arg0, _arg1)		\
	{						\
		.id = (_id),				\
		.name = #_id,				\
		.enabled = (_enabled),			\
		.needs_arg0 = (_arg0),			\
		.needs_arg1 = (_arg1),			\
	}

/*
 * Wrapper for instructions with no input operands.
 *
 * The instruction is emitted at label 1 so extable can recover from faults.
 * vec gets EAX on the fault path, matching the existing pattern.
 * rip_out receives the RIP of the instruction site.
 */
#define DEFINE_OPCODE_WRAPPER0(fn_name, insn_asm, clobbers...)		\
	int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)	\
	{								\
		int rc;							\
		int vec;						\
		u64 rip;						\
									\
		(void)arg0;						\
		(void)arg1;						\
									\
		asm volatile(						\
			"movl $0, %[rc]\n\t"				\
			"movl $1, %%ecx\n\t"				\
			"movl $-1, %[vec]\n\t"				\
			"leaq 1f(%%rip), %[rip]\n\t"			\
			"1:\n\t" insn_asm "\n\t"				\
			"2:\n\t"					\
			".section .fixup,\"ax\"\n\t"			\
			"3:\n\t"					\
			"movl %%eax, %[vec]\n\t"				\
			"movl $-1, %[rc]\n\t"				\
			"jmp 2b\n\t"					\
			".previous\n\t" _ASM_EXTABLE_FAULT(1b, 3b)	\
			: [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip) \
			:						\
			: "rax", "ecx", "cc", "memory", ##clobbers);	\
									\
		if (out) {						\
			out->rc = rc;					\
			out->vec = vec;					\
			out->rip = rip;					\
		}							\
									\
		return rc;						\
	}

/*
 * Wrapper for instructions that need arg0 in RAX.
 */
#define DEFINE_OPCODE_WRAPPER_RAX(fn_name, insn_asm, clobbers...)	\
	int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)	\
	{								\
		int rc;							\
		int vec;						\
		u64 rip;						\
									\
		(void)arg1;						\
									\
		asm volatile(						\
			"movl $0, %[rc]\n\t"				\
			"movl $-1, %[vec]\n\t"				\
			"mov %[arg0], %%rax\n\t"				\
			"leaq 1f(%%rip), %[rip]\n\t"			\
			"1: " insn_asm "\n\t"				\
			"2:\n\t"					\
			".section .fixup,\"ax\"\n\t"			\
			"3:\n\t"					\
			"movl %%eax, %[vec]\n\t"				\
			"movl $-1, %[rc]\n\t"				\
			"jmp 2b\n\t"					\
			".previous\n\t" _ASM_EXTABLE_FAULT(1b, 3b)	\
			: [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip) \
			: [arg0] "r"(arg0)				\
			: "rax", "cc", "memory", ##clobbers);		\
									\
		if (out) {						\
			out->rc = rc;					\
			out->vec = vec;					\
			out->rip = rip;					\
		}							\
									\
		return rc;						\
	}

/*
 * Wrapper for instructions that need arg0 in RAX and arg1 in RCX.
 */
#define DEFINE_OPCODE_WRAPPER_RAX_RCX(fn_name, insn_asm, clobbers...)	\
	int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)	\
	{								\
		int rc;							\
		int vec;						\
		u64 rip;						\
									\
		asm volatile(						\
			"movl $0, %[rc]\n\t"				\
			"movl $-1, %[vec]\n\t"				\
			"mov %[arg0], %%rax\n\t"				\
			"mov %[arg1], %%rcx\n\t"				\
			"leaq 1f(%%rip), %[rip]\n\t"			\
			"1: " insn_asm "\n\t"				\
			"2:\n\t"					\
			".section .fixup,\"ax\"\n\t"			\
			"3:\n\t"					\
			"movl %%eax, %[vec]\n\t"				\
			"movl $-1, %[rc]\n\t"				\
			"jmp 2b\n\t"					\
			".previous\n\t" _ASM_EXTABLE_FAULT(1b, 3b)	\
			: [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip) \
			: [arg0] "r"(arg0), [arg1] "r"(arg1)		\
			: "rax", "rcx", "cc", "memory", ##clobbers);	\
									\
		if (out) {						\
			out->rc = rc;					\
			out->vec = vec;					\
			out->rip = rip;					\
		}							\
									\
		return rc;						\
	}

/*
 * Wrapper for instructions that need arg0 in EAX and arg1 in ECX.
 * Useful for benign test patterns where only the low 32 bits matter.
 */
#define DEFINE_OPCODE_WRAPPER_EAX_ECX(fn_name, insn_asm, clobbers...)	\
	int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)	\
	{								\
		int rc;							\
		int vec;						\
		u64 rip;						\
		u32 a0 = (u32)arg0;					\
		u32 a1 = (u32)arg1;					\
									\
		asm volatile(						\
			"movl $0, %[rc]\n\t"				\
			"movl $-1, %[vec]\n\t"				\
			"mov %[arg0], %%eax\n\t"				\
			"mov %[arg1], %%ecx\n\t"				\
			"leaq 1f(%%rip), %[rip]\n\t"			\
			"1: " insn_asm "\n\t"				\
			"2:\n\t"					\
			".section .fixup,\"ax\"\n\t"			\
			"3:\n\t"					\
			"movl %%eax, %[vec]\n\t"				\
			"movl $-1, %[rc]\n\t"				\
			"jmp 2b\n\t"					\
			".previous\n\t" _ASM_EXTABLE_FAULT(1b, 3b)	\
			: [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip) \
			: [arg0] "r"(a0), [arg1] "r"(a1)		\
			: "rax", "rcx", "rbx", "rdx", "cc", "memory", ##clobbers); \
									\
		if (out) {						\
			out->rc = rc;					\
			out->vec = vec;					\
			out->rip = rip;					\
		}							\
									\
		return rc;						\
	}

/*
 * Wrapper for instructions that use DX as a port register.
 */
#define DEFINE_OPCODE_WRAPPER_DX(fn_name, insn_asm, clobbers...)	\
	int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)	\
	{								\
		int rc;							\
		int vec;						\
		u64 rip;						\
		u16 port = (u16)arg0;					\
									\
		(void)arg1;						\
									\
		asm volatile(						\
			"movl $0, %[rc]\n\t"				\
			"movl $-1, %[vec]\n\t"				\
			"mov %[port], %%dx\n\t"				\
			"leaq 1f(%%rip), %[rip]\n\t"			\
			"1: " insn_asm "\n\t"				\
			"2:\n\t"					\
			".section .fixup,\"ax\"\n\t"			\
			"3:\n\t"					\
			"movl %%eax, %[vec]\n\t"				\
			"movl $-1, %[rc]\n\t"				\
			"jmp 2b\n\t"					\
			".previous\n\t" _ASM_EXTABLE_FAULT(1b, 3b)	\
			: [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip) \
			: [port] "r"(port)				\
			: "rax", "rdx", "cc", "memory", ##clobbers);	\
									\
		if (out) {						\
			out->rc = rc;					\
			out->vec = vec;					\
			out->rip = rip;					\
		}							\
									\
		return rc;						\
	}

#define DEFINE_OPCODE_WRAPPER_IOSTRING(fn_name, insn_asm)		\
	int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)	\
	{								\
		int rc;							\
		int vec;						\
		u64 rip;						\
		void *buf = (void *)arg1;					\
		u32 port = (u32)arg0;					\
									\
		asm volatile(						\
			"mov %[buf], %%rdi\n\t"				\
			"mov %[port], %%edx\n\t"				\
			"movl $10, %%ecx\n\t"				\
			"movl $0, %[rc]\n\t"				\
			"movl $-1, %[vec]\n\t"				\
			"leaq 1f(%%rip), %[rip]\n\t"			\
			"1: " insn_asm "\n\t"				\
			"2:\n\t"					\
			".section .fixup,\"ax\"\n\t"			\
			"3:\n\t"					\
			"movl %%eax, %[vec]\n\t"				\
			"movl $-1, %[rc]\n\t"				\
			"jmp 2b\n\t"					\
			".previous\n\t" _ASM_EXTABLE_FAULT(1b, 3b)	\
			: [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip) \
			: [port] "r"(port), [buf] "r"(buf)		\
			: "rax", "edx", "rdi", "ecx", "memory", "cc"); \
									\
		if (out) {						\
			out->rc = rc;					\
			out->vec = vec;					\
			out->rip = rip;					\
		}							\
									\
		return rc;						\
	}

/*
 * EDX:EAX result producer, no input args.
 */
#define DEFINE_OPCODE_WRAPPER_EDX_EAX_OUT0(fn_name, insn_asm, clobbers...) \
	int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)	\
	{								\
		int rc;							\
		int vec;						\
		u64 rip;						\
		u32 lo = 0, hi = 0;					\
									\
		(void)arg0;						\
		(void)arg1;						\
									\
		asm volatile(						\
			"movl $0, %[rc]\n\t"				\
			"movl $-1, %[vec]\n\t"				\
			"leaq 1f(%%rip), %[rip]\n\t"			\
			"1: " insn_asm "\n\t"				\
			"movl %%eax, %[lo]\n\t"				\
			"movl %%edx, %[hi]\n\t"				\
			"2:\n\t"					\
			".section .fixup,\"ax\"\n\t"			\
			"3:\n\t"					\
			"movl %%eax, %[vec]\n\t"				\
			"movl $-1, %[rc]\n\t"				\
			"jmp 2b\n\t"					\
			".previous\n\t" _ASM_EXTABLE_FAULT(1b, 3b)	\
			: [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip), \
			  [lo] "=&r"(lo), [hi] "=&r"(hi)		\
			:						\
			: "rax", "rdx", "cc", "memory", ##clobbers);	\
									\
		if (out) {						\
			out->rc = rc;					\
			out->vec = vec;					\
			out->rip = rip;					\
		}							\
									\
		return rc;						\
	}

/*
 * ECX input, EDX:EAX output. Useful for RDPMC.
 */
#define DEFINE_OPCODE_WRAPPER_ECX_EDX_EAX_OUT(fn_name, insn_asm, clobbers...) \
	int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)	\
	{								\
		int rc;							\
		int vec;						\
		u64 rip;						\
		u32 ecx_in = (u32)arg0;					\
		u32 lo = 0, hi = 0;					\
									\
		(void)arg1;						\
									\
		asm volatile(						\
			"movl $0, %[rc]\n\t"				\
			"movl $-1, %[vec]\n\t"				\
			"mov %[ecx_in], %%ecx\n\t"			\
			"leaq 1f(%%rip), %[rip]\n\t"			\
			"1: " insn_asm "\n\t"				\
			"movl %%eax, %[lo]\n\t"				\
			"movl %%edx, %[hi]\n\t"				\
			"2:\n\t"					\
			".section .fixup,\"ax\"\n\t"			\
			"3:\n\t"					\
			"movl %%eax, %[vec]\n\t"				\
			"movl $-1, %[rc]\n\t"				\
			"jmp 2b\n\t"					\
			".previous\n\t" _ASM_EXTABLE_FAULT(1b, 3b)	\
			: [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip), \
			  [lo] "=&r"(lo), [hi] "=&r"(hi)		\
			: [ecx_in] "r"(ecx_in)				\
			: "rax", "rcx", "rdx", "cc", "memory", ##clobbers); \
									\
		if (out) {						\
			out->rc = rc;					\
			out->vec = vec;					\
			out->rip = rip;					\
		}							\
									\
		return rc;						\
	}

/*
 * One pointer argument, used as a memory operand. Useful for CLFLUSH.
 * arg0 = address
 */
#define DEFINE_OPCODE_WRAPPER_MEMARG0(fn_name, insn_asm, clobbers...)	\
	int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)	\
	{								\
		int rc;							\
		int vec;						\
		u64 rip;						\
		void *p = (void *)arg0;					\
									\
		(void)arg1;						\
									\
		asm volatile(						\
			"movl $0, %[rc]\n\t"				\
			"movl $-1, %[vec]\n\t"				\
			"leaq 1f(%%rip), %[rip]\n\t"			\
			"1: " insn_asm "\n\t"				\
			"2:\n\t"					\
			".section .fixup,\"ax\"\n\t"			\
			"3:\n\t"					\
			"movl %%eax, %[vec]\n\t"				\
			"movl $-1, %[rc]\n\t"				\
			"jmp 2b\n\t"					\
			".previous\n\t" _ASM_EXTABLE_FAULT(1b, 3b)	\
			: [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip) \
			: [mem] "m"(*(char *)p)				\
			: "rax", "cc", "memory", ##clobbers);		\
									\
		if (out) {						\
			out->rc = rc;					\
			out->vec = vec;					\
			out->rip = rip;					\
		}							\
									\
		return rc;						\
	}

#define DEFINE_OPCODE_WRAPPER_WRMSR(fn_name)				\
	int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)	\
	{								\
		int rc;							\
		int vec;						\
		u64 rip;						\
		u32 msr = (u32)arg0;					\
		u32 low = (u32)arg1;					\
		u32 high = (u32)(arg1 >> 32);				\
									\
		asm volatile(						\
			"movl $0, %[rc]\n\t"				\
			"movl $-1, %[vec]\n\t"				\
			"leaq 1f(%%rip), %[rip]\n\t"			\
			"1: wrmsr\n\t"					\
			"2:\n\t"					\
			".section .fixup,\"ax\"\n\t"			\
			"3:\n\t"					\
			"movl %%eax, %[vec]\n\t"				\
			"movl $-1, %[rc]\n\t"				\
			"jmp 2b\n\t"					\
			".previous\n\t" _ASM_EXTABLE_FAULT(1b, 3b)	\
			: [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip) \
			: "c"(msr), "a"(low), "d"(high)			\
			: "cc", "memory");				\
									\
		if (out) {						\
			out->rc = rc;					\
			out->vec = vec;					\
			out->rip = rip;					\
		}							\
									\
		return rc;						\
	}

#define DEFINE_OPCODE_WRAPPER_RDMSR(fn_name)				\
	int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)	\
	{								\
		int rc;							\
		int vec;						\
		u64 rip;						\
		u32 ecx_out = 0;					\
									\
		(void)arg0;						\
		(void)arg1;						\
									\
		asm volatile(						\
			"movl $0, %[rc]\n\t"				\
			"movl $-1, %[vec]\n\t"				\
			"leaq 1f(%%rip), %[rip]\n\t"			\
			"movl $0xc0000103, %%ecx\n\t"			\
			"1:\n\t"					\
			".byte 0xf3, 0xf3, 0x0f, 0x32\n\t"		\
			"movl %%ecx, %[ecx_out]\n\t"			\
			"2:\n\t"					\
			".section .fixup,\"ax\"\n\t"			\
			"3:\n\t"					\
			"movl %%eax, %[vec]\n\t"				\
			"movl %%ecx, %[ecx_out]\n\t"			\
			"movl $-1, %[rc]\n\t"				\
			"jmp 2b\n\t"					\
			".previous\n\t" _ASM_EXTABLE_FAULT(1b, 3b)	\
			: [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip), \
			  [ecx_out] "=&r"(ecx_out)			\
			:						\
			: "rax", "rcx", "rdx", "cc", "memory");	\
									\
		if (out) {						\
			out->rc = rc;					\
			out->vec = vec;					\
			out->rip = rip;					\
		}							\
									\
		return rc;						\
	}

#define DEFINE_OPCODE_WRAPPER_REP_MOVSQ(fn_name, clobbers...)		\
	int fn_name(u64 src, u64 dst, u64 count, struct opcode_result *out) \
	{								\
		int rc;							\
		int vec;						\
		u64 rip;						\
									\
		asm volatile(						\
			"movl $0, %[rc]\n\t"				\
			"movl $-1, %[vec]\n\t"				\
			"mov %[src], %%rsi\n\t"				\
			"mov %[dst], %%rdi\n\t"				\
			"mov %[count], %%rcx\n\t"			\
			"leaq 1f(%%rip), %[rip]\n\t"			\
			"1: rep movsq\n\t"				\
			"2:\n\t"					\
			".section .fixup,\"ax\"\n\t"			\
			"3:\n\t"					\
			"movl %%eax, %[vec]\n\t"				\
			"movl $-1, %[rc]\n\t"				\
			"jmp 2b\n\t"					\
			".previous\n\t" _ASM_EXTABLE_FAULT(1b, 3b)	\
			: [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip) \
			: [src] "r"(src), [dst] "r"(dst), [count] "r"(count) \
			: "rax", "rcx", "rsi", "rdi", "cc", "memory", ##clobbers); \
									\
		if (out) {						\
			out->rc = rc;					\
			out->vec = vec;					\
			out->rip = rip;					\
		}							\
									\
		return rc;						\
	}

#define DEFINE_OPCODE_WRAPPER_WRITE64(fn_name, clobbers...)		\
	int fn_name(u64 val, u64 dst, struct opcode_result *out)	\
	{								\
		int rc;							\
		int vec;						\
		u64 rip;						\
									\
		asm volatile(						\
			"movl $0, %[rc]\n\t"				\
			"movl $-1, %[vec]\n\t"				\
			"mov %[val], %%rax\n\t"				\
			"mov %[dst], %%rdi\n\t"				\
			"leaq 1f(%%rip), %[rip]\n\t"			\
			"1: mov %%rax, (%%rdi)\n\t"			\
			"2:\n\t"					\
			".section .fixup,\"ax\"\n\t"			\
			"3:\n\t"					\
			"movl %%eax, %[vec]\n\t"				\
			"movl $-1, %[rc]\n\t"				\
			"jmp 2b\n\t"					\
			".previous\n\t" _ASM_EXTABLE_FAULT(1b, 3b)	\
			: [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip) \
			: [val] "r"(val), [dst] "r"(dst)		\
			: "rax", "rdi", "cc", "memory", ##clobbers);	\
									\
		if (out) {						\
			out->rc = rc;					\
			out->vec = vec;					\
			out->rip = rip;					\
		}							\
									\
		return rc;						\
	}

#define DEFINE_RMPUPDATE_PRE_GUEST_WRAPPER(fn_name, clobbers...)		\
int fn_name(u64 paddr, u64 asid, struct opcode_result *out)			\
{									\
	struct rmp_state state = { 0 };					\
	u64 ret;							\
	int rc;								\
	int vec;							\
	u64 rip;							\
									\
	state.assigned = 1;						\
	state.pagesize = 0x1000;					\
	state.immutable = 0;						\
	state.asid = (u32)asid;						\
									\
	asm volatile(							\
		"movl $0, %[rc]\n\t"					\
		"movl $-1, %[vec]\n\t"				\
		"mov %[paddr], %%rax\n\t"				\
		"mov %[state], %%rcx\n\t"				\
		"leaq 1f(%%rip), %[rip]\n\t"			\
		"1: .byte 0xF2, 0x0F, 0x01, 0xFE\n\t" /* RMPUPDATE */\
		"2:\n\t"						\
		".section .fixup,\"ax\"\n\t"			\
		"3:\n\t"						\
		"movl %%eax, %[vec]\n\t"				\
		"movl $-1, %[rc]\n\t"				\
		"jmp 2b\n\t"					\
		".previous\n\t"					\
		_ASM_EXTABLE_FAULT(1b, 3b)			\
		: [ret] "=a"(ret),					\
		  [rc] "=&r"(rc),					\
		  [vec] "=&r"(vec),					\
		  [rip] "=&r"(rip)					\
		: [paddr] "r"(paddr),				\
		  [state] "r"((unsigned long)&state)		\
		: "rcx", "cc", "memory", ##clobbers);		\
									\
	if (out) {							\
		out->rc = rc;						\
		out->vec = vec;						\
		out->rip = rip;						\
	}								\
									\
	return rc ? rc : ret;					\
}

#define DEFINE_OPCODE_WRAPPER_ECX_EDX_EAX_OUT0(fn_name, insn_asm, clobbers...) \
	int fn_name(u64 arg0, u64 arg1, struct opcode_result *out)	\
	{								\
		int rc;							\
		int vec;						\
		u64 rip;						\
		u32 aux = 0, lo = 0, hi = 0;				\
									\
		(void)arg0;						\
		(void)arg1;						\
									\
		asm volatile(						\
			"movl $0, %[rc]\n\t"				\
			"movl $-1, %[vec]\n\t"				\
			"leaq 1f(%%rip), %[rip]\n\t"			\
			"1: " insn_asm "\n\t"				\
			"movl %%ecx, %[aux]\n\t"				\
			"movl %%eax, %[lo]\n\t"				\
			"movl %%edx, %[hi]\n\t"				\
			"2:\n\t"					\
			".section .fixup,\"ax\"\n\t"			\
			"3:\n\t"					\
			"movl %%eax, %[vec]\n\t"				\
			"movl $-1, %[rc]\n\t"				\
			"jmp 2b\n\t"					\
			".previous\n\t" _ASM_EXTABLE_FAULT(1b, 3b)	\
			: [rc] "=&r"(rc), [vec] "=&r"(vec), [rip] "=&r"(rip), \
			  [aux] "=&r"(aux), [lo] "=&r"(lo), [hi] "=&r"(hi) \
			:						\
			: "rax", "rcx", "rdx", "cc", "memory", ##clobbers); \
									\
		if (out) {						\
			out->rc = rc;					\
			out->vec = vec;					\
			out->rip = rip;					\
			/* Store aux/lo/hi too if struct gains fields for them. */ \
		}							\
									\
		return rc;						\
	}

struct opcode_desc opcode_table[] = {
	OPENTRY(OP_NOP, true, false, false),
	OPENTRY(OP_PAUSE, true, false, false),
	OPENTRY(OP_CPUID, true, true, true),
	OPENTRY(OP_UD2, true, false, false),
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
	OPENTRY(OP_PREFETCHNTA, true, true, false),
	OPENTRY(OP_PREFETCHNTAT1, true, true, false),
	OPENTRY(OP_READ_CR0, true, false, false),
	OPENTRY(OP_READ_CR2, true, false, false),
	OPENTRY(OP_READ_CR3, true, false, false),
	OPENTRY(OP_READ_CR4, true, false, false),
	OPENTRY(OP_RDMSR, true, true, false),
	OPENTRY(OP_CUSTOM1, true, true, true),
	OPENTRY(OP_AVX, true, true, true),
	OPENTRY(OP_MOVL, true, true, true),
	OPENTRY(OP_VMRUN, true, true, false),
	OPENTRY(OP_VMLOAD, true, true, false),
	OPENTRY(OP_SKINIT, true, true, true),
	OPENTRY(OP_HLT, true, false, false),
	{},
};

DEFINE_OPCODE_WRAPPER0(try_nop, "nop")
DEFINE_OPCODE_WRAPPER0(try_wbinvd, "wbinvd")
DEFINE_OPCODE_WRAPPER0(try_pause, "pause")
DEFINE_OPCODE_WRAPPER_EAX_ECX(try_cpuid, "cpuid")
DEFINE_OPCODE_WRAPPER_EAX_ECX(try_skinit, "SKINIT")
DEFINE_OPCODE_WRAPPER0(try_ud2, "ud2")
DEFINE_OPCODE_WRAPPER0(try_hlt, "STI;hlt")

DEFINE_OPCODE_WRAPPER0(try_in_imm_e4, ".byte 0xe4, 0x88")
DEFINE_OPCODE_WRAPPER0(try_in_imm_e5, ".byte 0xe5, 0x80")

DEFINE_OPCODE_WRAPPER0(try_out_imm_e6, ".byte 0xe6, 0x80")
DEFINE_OPCODE_WRAPPER0(try_out_imm_e7, ".byte 0xe7, 0x80")

DEFINE_OPCODE_WRAPPER_DX(try_in_dx_ec, "in %%dx, %%al")
DEFINE_OPCODE_WRAPPER_DX(try_in_dx_ed, "in %%dx, %%eax")

DEFINE_OPCODE_WRAPPER_DX(try_out_dx_ee, "out %%al, %%dx")
DEFINE_OPCODE_WRAPPER_DX(try_out_dx_ef, "out %%ax, %%dx")

DEFINE_OPCODE_WRAPPER_IOSTRING(try_insb, "insb")
DEFINE_OPCODE_WRAPPER_IOSTRING(try_insd, "insl")
DEFINE_OPCODE_WRAPPER_IOSTRING(try_outsb, "outsb")
DEFINE_OPCODE_WRAPPER_IOSTRING(try_outsd, "outsl")

DEFINE_OPCODE_WRAPPER_EDX_EAX_OUT0(try_rdtsc, "rdtsc")
DEFINE_OPCODE_WRAPPER_ECX_EDX_EAX_OUT(try_rdpmc, "rdpmc")
DEFINE_OPCODE_WRAPPER_MEMARG0(try_clflushopt, "clflushopt %[mem]")
DEFINE_OPCODE_WRAPPER_MEMARG0(try_clwb, "clwb %[mem]")
DEFINE_OPCODE_WRAPPER_MEMARG0(try_invlpg, "invlpg %[mem]")

DEFINE_OPCODE_WRAPPER_WRMSR(do_wrmsr);

DEFINE_OPCODE_WRAPPER_RAX(try_vmsave, "vmsave %%rax")
DEFINE_OPCODE_WRAPPER_RAX(try_vmrun, "vmrun %%rax")
DEFINE_OPCODE_WRAPPER_RAX(try_vmload, "vmload %%rax")
DEFINE_OPCODE_WRAPPER_REP_MOVSQ(test_rep_movsq);

DEFINE_OPCODE_WRAPPER_MEMARG0(try_sidt, "sidt %[mem]")
DEFINE_OPCODE_WRAPPER_MEMARG0(try_sgdt, "sgdt %[mem]")

DEFINE_OPCODE_WRAPPER_RAX(try_monitor, "monitor")

DEFINE_OPCODE_WRAPPER_RAX_RCX(try_udbgrd, ".byte 0x0f, 0x0e")
DEFINE_RMPUPDATE_PRE_GUEST_WRAPPER(try_rmpupdate)

DEFINE_OPCODE_WRAPPER_ECX_EDX_EAX_OUT0(try_rdtscp, "rdtscp")
DEFINE_OPCODE_WRAPPER0(try_lfence, "lfence")

DEFINE_OPCODE_WRAPPER_MEMARG0(try_prefetchta, "prefetchnta %[mem]")
DEFINE_OPCODE_WRAPPER_MEMARG0(try_prefetchwt1, "prefetchwt1 %[mem]")

DEFINE_OPCODE_WRAPPER0(try_read_cr0, "mov %%cr0, %%rax")
DEFINE_OPCODE_WRAPPER0(try_read_cr2, "mov %%cr2, %%rax")
DEFINE_OPCODE_WRAPPER0(try_read_cr3, "mov %%cr3, %%rax")
DEFINE_OPCODE_WRAPPER0(try_read_cr4, "mov %%cr4, %%rax")

DEFINE_OPCODE_WRAPPER_RDMSR(try_rdmsr)

DEFINE_OPCODE_WRAPPER_WRITE64(try_write64)

static void ex_vpgatherdd(const int *base, const int *idx, int *out)
{
    asm volatile(
        "vmovdqu   (%[idx]), %%ymm1\n\t"      /* indices */
        "vpcmpeqd  %%ymm2, %%ymm2, %%ymm2\n\t"/* mask = all ones */
        "vpxor     %%ymm0, %%ymm0, %%ymm0\n\t"/* dest seed */
        "vpgatherdd %%ymm2, (%[base],%%ymm1,4), %%ymm0\n\t"
        "vmovdqu   %%ymm0, (%[out])\n\t"
        "vzeroupper\n\t"
        :
        : [base]"r"(base), [idx]"r"(idx), [out]"r"(out)
        : "ymm0", "ymm1", "ymm2", "memory"
    );
}

static void ex_vpgatherdd_masked(const int *base,
                                 const int *idx,
                                 const int *mask,
                                 int *out)
{
    asm volatile(
        "vmovdqu    (%[idx]), %%ymm1\n\t"                 // indices
        "vmovdqu    (%[mask]), %%ymm2\n\t"                // sign bit selects active lanes
        "vpxor      %%ymm0, %%ymm0, %%ymm0\n\t"           // seed dst = 0
        "vpgatherdd %%ymm2, (%[base],%%ymm1,4), %%ymm0\n\t"
        "vmovdqu    %%ymm0, (%[out])\n\t"
        "vzeroupper\n\t"
        :
        : [base]"r"(base), [idx]"r"(idx), [mask]"r"(mask), [out]"r"(out)
        : "ymm0", "ymm1", "ymm2", "memory"
    );
}

static void ex_vgatherdps(const float *base, const int *idx, float *out)
{
    asm volatile(
        "vmovdqu    (%[idx]), %%ymm1\n\t"
        "vpcmpeqd   %%ymm2, %%ymm2, %%ymm2\n\t"
        "vxorps     %%ymm0, %%ymm0, %%ymm0\n\t"
        "vgatherdps %%ymm2, (%[base],%%ymm1,4), %%ymm0\n\t"
        "vmovups    %%ymm0, (%[out])\n\t"
        "vzeroupper\n\t"
        :
        : [base]"r"(base), [idx]"r"(idx), [out]"r"(out)
        : "ymm0", "ymm1", "ymm2", "memory"
    );
}

static void ex_vpermd(const int *src, const int *perm, int *out)
{
    asm volatile(
        "vmovdqu (%[src]), %%ymm1\n\t"
        "vmovdqu (%[perm]), %%ymm2\n\t"
        "vpermd  %%ymm1, %%ymm2, %%ymm0\n\t"
        "vmovdqu %%ymm0, (%[out])\n\t"
        "vzeroupper\n\t"
        :
        : [src]"r"(src), [perm]"r"(perm), [out]"r"(out)
        : "ymm0", "ymm1", "ymm2", "memory"
    );
}

static void ex_vpermps(const float *src, const int *perm, float *out)
{
    asm volatile(
        "vmovups (%[src]), %%ymm1\n\t"
        "vmovdqu (%[perm]), %%ymm2\n\t"
        "vpermps %%ymm1, %%ymm2, %%ymm0\n\t"
        "vmovups %%ymm0, (%[out])\n\t"
        "vzeroupper\n\t"
        :
        : [src]"r"(src), [perm]"r"(perm), [out]"r"(out)
        : "ymm0", "ymm1", "ymm2", "memory"
    );
}

static void ex_vpshufb(const unsigned char *src,
                              const unsigned char *ctl,
                              unsigned char *out)
{
    asm volatile(
        "vmovdqu (%[src]), %%ymm1\n\t"
        "vmovdqu (%[ctl]), %%ymm2\n\t"
        "vpshufb %%ymm2, %%ymm1, %%ymm0\n\t"
        "vmovdqu %%ymm0, (%[out])\n\t"
        "vzeroupper\n\t"
        :
        : [src]"r"(src), [ctl]"r"(ctl), [out]"r"(out)
        : "ymm0", "ymm1", "ymm2", "memory"
    );
}

static void ex_vpmaskmovd_store(int *dst, const int *src, const int *mask)
{
    asm volatile(
        "vmovdqu    (%[src]), %%ymm0\n\t"
        "vmovdqu    (%[mask]), %%ymm1\n\t"
        "vpmaskmovd %%ymm0, %%ymm1, (%[dst])\n\t"
        "vzeroupper\n\t"
        :
        : [dst]"r"(dst), [src]"r"(src), [mask]"r"(mask)
        : "ymm0", "ymm1", "memory"
    );
}

//here there is an address (uop 102), might be intresting in guest
static void ex_vpmaskmovps_load(const float *src, const int *mask, float *out)
{
    asm volatile(
        "vmovdqu    (%[mask]), %%ymm1\n\t"
        "vpmaskmovd (%[src]), %%ymm1, %%ymm0\n\t"
        "vmovups    %%ymm0, (%[out])\n\t"
        "vzeroupper\n\t"
        :
        : [src]"r"(src), [mask]"r"(mask), [out]"r"(out)
        : "ymm0", "ymm1", "memory"
    );
}

static void ex_vblendvps(const float *a, const float *b, const int *mask, float *out)
{
    asm volatile(
        "vmovups   (%[a]), %%ymm1\n\t"
        "vmovups   (%[b]), %%ymm2\n\t"
        "vmovdqu   (%[m]), %%ymm3\n\t"
        "vblendvps %%ymm3, %%ymm2, %%ymm1, %%ymm0\n\t"
        "vmovups   %%ymm0, (%[out])\n\t"
        "vzeroupper\n\t"
        :
        : [a]"r"(a), [b]"r"(b), [m]"r"(mask), [out]"r"(out)
        : "ymm0", "ymm1", "ymm2", "ymm3", "memory"
    );
}

static void ex_vpmulld(const int *a, const int *b, int *out)
{
    asm volatile(
        "vmovdqu (%[a]), %%ymm1\n\t"
        "vmovdqu (%[b]), %%ymm2\n\t"
        "vpmulld %%ymm2, %%ymm1, %%ymm0\n\t"
        "vmovdqu %%ymm0, (%[out])\n\t"
        "vzeroupper\n\t"
        :
        : [a]"r"(a), [b]"r"(b), [out]"r"(out)
        : "ymm0", "ymm1", "ymm2", "memory"
    );
}

static void ex_vpmuludq(const unsigned int *a,
                               const unsigned int *b,
                               unsigned long long *out)
{
    asm volatile(
        "vmovdqu   (%[a]), %%ymm1\n\t"
        "vmovdqu   (%[b]), %%ymm2\n\t"
        "vpmuludq  %%ymm2, %%ymm1, %%ymm0\n\t"
        "vmovdqu   %%ymm0, (%[out])\n\t"
        "vzeroupper\n\t"
        :
        : [a]"r"(a), [b]"r"(b), [out]"r"(out)
        : "ymm0", "ymm1", "ymm2", "memory"
    );
}

static void ex_vpmaddubsw(const unsigned char *a,
                                 const signed char *b,
                                 short *out)
{
    asm volatile(
        "vmovdqu     (%[a]), %%ymm1\n\t"
        "vmovdqu     (%[b]), %%ymm2\n\t"
        "vpmaddubsw  %%ymm2, %%ymm1, %%ymm0\n\t"
        "vmovdqu     %%ymm0, (%[out])\n\t"
        "vzeroupper\n\t"
        :
        : [a]"r"(a), [b]"r"(b), [out]"r"(out)
        : "ymm0", "ymm1", "ymm2", "memory"
    );
}

static void ex_vpmaddwd(const short *a, const short *b, int *out)
{
    asm volatile(
        "vmovdqu   (%[a]), %%ymm1\n\t"
        "vmovdqu   (%[b]), %%ymm2\n\t"
        "vpmaddwd  %%ymm2, %%ymm1, %%ymm0\n\t"
        "vmovdqu   %%ymm0, (%[out])\n\t"
        "vzeroupper\n\t"
        :
        : [a]"r"(a), [b]"r"(b), [out]"r"(out)
        : "ymm0", "ymm1", "ymm2", "memory"
    );
}

static void ex_vfmaddsub231ps(const float *a,
                                     const float *b,
                                     const float *c,
                                     float *out)
{
    asm volatile(
        "vmovups            (%[a]), %%ymm0\n\t"
        "vmovups            (%[b]), %%ymm1\n\t"
        "vmovups            (%[c]), %%ymm2\n\t"
        "vfmaddsub231ps     %%ymm2, %%ymm1, %%ymm0\n\t"
        "vmovups            %%ymm0, (%[out])\n\t"
        "vzeroupper\n\t"
        :
        : [a]"r"(a), [b]"r"(b), [c]"r"(c), [out]"r"(out)
        : "ymm0", "ymm1", "ymm2", "memory"
    );
}

static void ex_vperm2i128(const int *a, const int *b, int *out)
{
    asm volatile(
        "vmovdqu    (%[a]), %%ymm1\n\t"
        "vmovdqu    (%[b]), %%ymm2\n\t"
        "vperm2i128 $0x21, %%ymm2, %%ymm1, %%ymm0\n\t"
        "vmovdqu    %%ymm0, (%[out])\n\t"
        "vzeroupper\n\t"
        :
        : [a]"r"(a), [b]"r"(b), [out]"r"(out)
        : "ymm0", "ymm1", "ymm2", "memory"
    );
}

static void ex_vpsllvd(const int *src, const int *counts, int *out)
{
    asm volatile(
        "vmovdqu  (%[src]), %%ymm1\n\t"
        "vmovdqu  (%[cnt]), %%ymm2\n\t"
        "vpsllvd  %%ymm2, %%ymm1, %%ymm0\n\t"
        "vmovdqu  %%ymm0, (%[out])\n\t"
        "vzeroupper\n\t"
        :
        : [src]"r"(src), [cnt]"r"(counts), [out]"r"(out)
        : "ymm0", "ymm1", "ymm2", "memory"
    );
}

static void ex_vpalignr(const unsigned char *a,
                               const unsigned char *b,
                               unsigned char *out)
{
    asm volatile(
        "vmovdqu   (%[a]), %%ymm1\n\t"
        "vmovdqu   (%[b]), %%ymm2\n\t"
        "vpalignr  $8, %%ymm2, %%ymm1, %%ymm0\n\t"
        "vmovdqu   %%ymm0, (%[out])\n\t"
        "vzeroupper\n\t"
        :
        : [a]"r"(a), [b]"r"(b), [out]"r"(out)
        : "ymm0", "ymm1", "ymm2", "memory"
    );
}

static void ex_vgatherdps_masked(const float *base,
                                 const int *idx,
                                 const int *mask,
                                 float *out)
{
    asm volatile(
        "vmovdqu    (%[idx]), %%ymm1\n\t"
        "vmovdqu    (%[mask]), %%ymm2\n\t"
        "vxorps     %%ymm0, %%ymm0, %%ymm0\n\t"
        "vgatherdps %%ymm2, (%[base],%%ymm1,4), %%ymm0\n\t"
        "vmovups    %%ymm0, (%[out])\n\t"
        "vzeroupper\n\t"
        :
        : [base]"r"(base), [idx]"r"(idx), [mask]"r"(mask), [out]"r"(out)
        : "ymm0", "ymm1", "ymm2", "memory"
    );
}

static __always_inline void flush_cache_line_fenced(const void *addr)
{
    asm volatile("mfence\n\t" ::: "memory");
    asm volatile("clflush (%0)\n\t" : : "r"(addr) : "memory");
    asm volatile("mfence\n\t" ::: "memory");
}

static void dump_i32(const char *name, const int *v, int n)
{
    char buf[256];
    int len = 0;

    len += scnprintf(buf + len, sizeof(buf) - len, "%s: [", name);

    for (int i = 0; i < n; i++) {
        len += scnprintf(buf + len, sizeof(buf) - len,
                         "%d%s",
                         v[i],
                         (i == n - 1) ? "" : ", ");
    }

    len += scnprintf(buf + len, sizeof(buf) - len, "]");

    pr_info("%s\n", buf);
}
static void dump_f32(const char *name, const float *v, int n)
{
    char buf[256];
    int len = 0;
    int i;

    len += scnprintf(buf + len, sizeof(buf) - len, "%s: [", name);

    for (i = 0; i < n; i++) {
        int ipart, frac;
        float x = v[i];

        /* print 3 digits after decimal point */
        ipart = (int)x;
        frac = (int)((x - (float)ipart) * 1000.0f);

        /* keep the sign on the integer part only */
        if (frac < 0)
            frac = -frac;

        len += scnprintf(buf + len, sizeof(buf) - len,
                         "%d.%03d%s",
                         ipart,
                         frac,
                         (i == n - 1) ? "" : ", ");
    }

    len += scnprintf(buf + len, sizeof(buf) - len, "]");

    pr_info("%s\n", buf);
}

static const int gather_base[8] = {0, 16 * 1, 16 * 2, 16 * 3, 16 * 4, 16 * 5, 16 * 6, 16 * 7};
static const int mask_all_ones[8] = { -1, 1, -1, 1, -1, -1, -1, 1};

static inline void prefetcht0_strict(const void *addr) {
    asm volatile("prefetcht0 (%0)" :: "r"(addr) : "memory");
}

static int run_avx(u64 arg0, u64 arg1, struct opcode_result *out)
{
	if (out) {
		out->rc = 0;
		out->vec = -1;
		out->rip = 0;
	}

    static int print_mask = 1;
    if(print_mask)
    {
		pr_info("gather_base va: %px\n", gather_base);
        pr_info("mask_all_ones va: %px\n", mask_all_ones);
        print_mask = 0;
    }

	kernel_fpu_begin();
	ex_vpgatherdd_masked((const int *)arg0,
			gather_base,
            mask_all_ones,
		    (int *)arg1);
	kernel_fpu_end();

    static int print_out = 1;
	print_out++;
    if (print_out>200) {
        dump_i32("out ", (const int *)arg1, 8);
		u64 time =  measure_access_time((uint8_t *)arg0 + gather_base[7] * 4);
		pr_info("Access time for %px: %llu cycles\n", (uint8_t *)arg0 + gather_base[7] * 4, time);
        print_out = 0;
    }

	return 0;
}

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
		return test_rep_movsq(arg0, arg1, 100, out);
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
	case OP_RMPUPDATE:
		return try_rmpupdate(arg0, arg1, out);
	case OP_LFENCE:
		return try_lfence(arg0, arg1, out);
	case OP_RDTSCP:
		return try_rdtscp(arg0, arg1, out);
	case OP_PREFETCHNTA:
		return try_prefetchta(arg0, arg1, out);
	case OP_PREFETCHNTAT1:
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
	case OP_AVX:
		return run_avx(arg0, arg1, out);
	case OP_MOVL:
		return try_write64(arg0, arg1, out);
	case OP_VMRUN:
		return try_vmrun(arg0, arg1, out);
	case OP_VMLOAD:
		return try_vmload(arg0, arg1, out);
	case OP_SKINIT:
		return try_skinit(arg0, arg1, out);
	case OP_HLT:
		return try_hlt(arg0, arg1, out);
	default:
		if (out) {
			out->rc = -1;
			out->vec = -1;
			out->rip = 0;
		}
		return -1;
	}
}