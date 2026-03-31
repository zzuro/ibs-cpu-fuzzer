#pragma once

struct opcode_result {
	int rc;
	int vec;
	u64 rip;
};

enum opcode_id {
	OP_NOP = 0,
	OP_PAUSE,
	OP_CPUID,
	OP_UD2,
	OP_IN_IMM_AL,
	OP_IN_IMM_EAX,
	OP_IN_DX_AL,
	OP_IN_DX_EAX,
	OP_OUT_IMM_AL,
	OP_OUT_IMM_EAX,
	OP_OUT_DX_AL,
	OP_OUT_DX_EAX,
	OP_INSB,
	OP_INSD,
	OP_OUTSB,
	OP_OUTSD,
	OP_RDTSC,
	OP_RDPMC,
	OP_CLFLUSH,
	OP_WRMSR,
	OP_VMSAVE,
	OP_MOVSQ,
	OP_SIDT,
	OP_SGDT,
	OP_WBINVD,
	OP_CLWB,
	OP_INVLPG,
	OP_MONITOR,
	OP_UDBGRD,
	OP_RMPUPDATE,
	OP_LFENCE,
	OP_RDTSCP,
	OP_PREFETCHW,
	OP_PREFETCHWT1,
	OP_READ_CR0,
	OP_READ_CR2,
	OP_READ_CR3,
	OP_READ_CR4,
	OP_RDMSR,
	OP_CUSTOM1,
	OP_AVX,
	OP_MOVL,
	OP_MAX,
};

struct opcode_desc {
	enum opcode_id id;
	const char *name;
	bool enabled;
	bool needs_arg0;
	bool needs_arg1;
};

extern struct opcode_desc opcode_table[];

int run_selected_opcode(enum opcode_id id, u64 arg0, u64 arg1,
			struct opcode_result *out);