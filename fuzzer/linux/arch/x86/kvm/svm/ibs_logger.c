#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "svm.h"
#include "ibs_logger.h"

#define CREATE_TRACE_POINTS
#include <trace/events/ibs.h>


static u32 get_flag(union ibs_op_data3 opData3, union ibs_op_data opData1)
{
	u32 flags = 0;
	if (opData3.ld_op)
		flags |= IBS_F_LOAD;
	if (opData3.st_op)
		flags |= IBS_F_STORE;
	if (opData3.dc_miss)
		flags |= IBS_F_DCMISS;
	if (opData3.dc_uc_mem_acc)
		flags |= IBS_F_UC;
	if (opData3.dc_wc_mem_acc)
		flags |= IBS_F_WC;
	if (opData1.op_brn_ret)
		flags |= IBS_F_BRNRET;
	if (opData1.op_microcode)
		flags |= IBS_F_MICRO;
	if (opData1.op_brn_fuse)
		flags |= IBS_F_BRNFUSE;

	return flags;
}

void ibs_trace_emit(u64 rip_value, u64 uop_cnt, u64 phys_addr, u64 lin_addr,
		    union ibs_op_data3 opData3, union ibs_op_data opData1)
{
	trace_ibs_event(rip_value, uop_cnt, phys_addr, lin_addr, opData3.op_mem_width,
			get_flag(opData3, opData1), opData1.tag_to_ret_ctr,
			opData1.comp_to_ret_ctr);
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