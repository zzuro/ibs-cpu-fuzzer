#pragma once

#include <linux/types.h>


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
    OP_MAX,
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
    OP_OUTSD
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

int try_nop(u64 arg0, u64 arg1, struct opcode_result *out);
int try_pause(u64 arg0, u64 arg1, struct opcode_result *out);
int try_cpuid(u64 arg0, u64 arg1, struct opcode_result *out);
int try_ud2(u64 arg0, u64 arg1, struct opcode_result *out);