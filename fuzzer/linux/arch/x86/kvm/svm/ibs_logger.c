#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "svm.h"
#include "ibs_logger.h"

#define CREATE_TRACE_POINTS
#include <trace/events/ibs.h>

static struct file *ibs_log_filp;

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
	trace_ibs_event(rip_value, uop_cnt, phys_addr, lin_addr,
			opData3.op_mem_width, get_flag(opData3, opData1),
			opData1.tag_to_ret_ctr, opData1.comp_to_ret_ctr);
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

int ibs_log_open(char *ibs_log_path)
{
	int err = 0;
	if (ibs_log_filp) {
		return 0;
	}

	ibs_log_filp =
		filp_open(ibs_log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (IS_ERR(ibs_log_filp)) {
		err = PTR_ERR(ibs_log_filp);
		ibs_log_filp = NULL;
	}

	return err;
}

void ibs_log_close(void)
{
	if (ibs_log_filp) {
		filp_close(ibs_log_filp, NULL);
		ibs_log_filp = NULL;
	}
}

void ibs_log_write_line(const char *line, size_t len)
{
	loff_t pos = 0;

	if (!ibs_log_filp) {
		return;
	}

	kernel_write(ibs_log_filp, line, len, &pos);
}

void ibs_log_event(uint64_t rip_value, uint64_t uop_cnt,
		   union ibs_op_data3 opData3, union ibs_op_data opData1,
		   uint64_t phys_addr, uint64_t lin_addr, char **memwithStrings)
{
	char *buf;
	int n;

	buf = kmalloc(512, GFP_KERNEL);
	if (!buf)
		return;

	if (opData3.ld_op == 1 || opData3.st_op == 1) {
		n = scnprintf(
			buf, 512,
			"[RIP: 0x%016llx][uop cnt: %lld] [%6s%s] 0x%016llx (v=0x%016llx) "
			"UC[%s] WC[%s] CacheMiss [%s] tagToRetire [%4d] compToRetire [%4d]\n",
			rip_value, uop_cnt, opData3.ld_op ? "load" : "store",
			memwithStrings[opData3.op_mem_width], phys_addr,
			lin_addr, opData3.dc_wc_mem_acc ? "+" : "-",
			opData3.dc_uc_mem_acc ? "+" : "-",
			opData3.dc_miss ? "+" : "-", opData1.tag_to_ret_ctr,
			opData1.comp_to_ret_ctr);
	} else {
		n = scnprintf(
			buf, 512,
			"[RIP: 0x%016llx][uop cnt: %lld] [%8s] Branch[%3s] tagToRetire [%4d] "
			"compToRetire [%4d] micro [%3s] multiOP [%3s]\n",
			rip_value, uop_cnt, "ALU",
			opData1.op_brn_ret ? "yes" : "no",
			opData1.tag_to_ret_ctr, opData1.comp_to_ret_ctr,
			opData1.op_microcode ? "yes" : "no",
			opData1.op_brn_fuse ? "yes" : "no");
	}

	ibs_log_write_line(buf, (size_t)n);
	kfree(buf);
}

char *ibs_generate_filename(const u8 *bytes, size_t len)
{
	size_t prefix_len = strlen(IBS_PREFIX);
	size_t suffix_len = strlen(IBS_SUFFIX);
	size_t needed;
	size_t i;
	char *path;
	char *p;

	needed = prefix_len + (len * 4) + suffix_len + 1;

	path = kmalloc(needed, GFP_KERNEL);
	if (!path)
		return NULL;

	p = path;

	/* Copy prefix */
	p += scnprintf(p, needed, "%s", IBS_PREFIX);

	/* Append encoded bytes */
	for (i = 0; i < len; i++)
		p += scnprintf(p, needed - (p - path), "\\x%02x", bytes[i]);

	/* Append suffix */
	scnprintf(p, needed - (p - path), "%s", IBS_SUFFIX);

	return path;
}
