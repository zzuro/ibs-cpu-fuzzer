#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "ibs_logger.h"

static struct file *ibs_log_filp;
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
