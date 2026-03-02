#pragma once
#include <linux/types.h>
#include <asm/amd/ibs.h>
#include "fuzzer.h"

void ibs_trace_emit(u64 rip_value, u64 uop_cnt, u64 phys_addr, u64 lin_addr,
		    union ibs_op_data3 opData3, union ibs_op_data opData1);

void ibs_trace_start(insn_t *insn);
void ibs_trace_finished(insn_t *insn);
