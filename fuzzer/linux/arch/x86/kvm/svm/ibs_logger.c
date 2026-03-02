#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "svm.h"
#include "ibs_logger.h"

#define CREATE_TRACE_POINTS
#include <trace/events/ibs.h>


void ibs_trace_emit(u64 rip_value, u64 uop_cnt, u64 phys_addr, u64 lin_addr,
		    union ibs_op_data3 opData3, union ibs_op_data opData1)
{
	trace_ibs_event(rip_value, uop_cnt, phys_addr, lin_addr,
			(u8)opData3.ld_op, (u8)opData3.st_op,
			(u8)opData3.op_mem_width, (u8)opData3.dc_miss,
			(u8)opData3.dc_uc_mem_acc, (u8)opData3.dc_wc_mem_acc,
			(u16)opData1.tag_to_ret_ctr,
			(u16)opData1.comp_to_ret_ctr);
}

void ibs_trace_start(insn_t *insn)
{
	u32 n = (insn->len < MAX_INSN_LENGTH) ? insn->len : MAX_INSN_LENGTH;
	trace_ibs_marker("START", insn->bytes, n);
}

void ibs_trace_finished(insn_t *insn)
{
	u32 n = (insn->len < MAX_INSN_LENGTH) ? insn->len : MAX_INSN_LENGTH;
	trace_ibs_marker("FINISHED", insn->bytes, n);
}