#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "svm.h"
#include "ibs_logger.h"

static struct file *ibs_log_filp;

int ibs_log_open(char *ibs_log_path, uint64_t *hpa, size_t len)
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
	}else {
		ibs_log_hpa(hpa, len);
		char* buf = kmalloc(512, GFP_KERNEL);
		if (!buf) {
			ibs_log_close();
			return -ENOMEM;
		}

		int n = scnprintf(buf, 512, "RIP,UOP_CNT,OP_TYPE,PHYS_ADDR,LIN_ADDR,UC_MEM_ACC,WC_MEM_ACC,DC_MISS,"
			"IbsOpMicrocode,IbsOpFuse,IbsOpBrnRet,IbsOpBrnMisp,IbsOpBrnTaken,BRANCH_TARGET_RIP,"
			"RAX,RBX,RCX,RDX,RSI,RDI,R8,R9,R10,R11,R12,R13,R14,R15,"
			"RSP,RBP,RFLAGS\n");
		ibs_log_write_line(buf, (size_t)n);
		kfree(buf);
	}

	return err;
}

void ibs_log_hpa(uint64_t *hpa, size_t len)
{
    char *buf;
    size_t buf_sz = 16384; 
    size_t n = 0;
    loff_t pos;
    int ret;

    buf = kmalloc(buf_sz, GFP_KERNEL);
    if (!buf) {
        return;
    }

    for (size_t i = 0; i < len; i++) {
        n += scnprintf(buf + n, buf_sz - n, "0x%016llx\n",
                       (unsigned long long)hpa[i]);

        if (n >= buf_sz - 32)
            break;
    }

    ret = kernel_write(ibs_log_filp, buf, n, &pos);
    if (ret < 0)
        pr_err("kernel_write failed: %d\n", ret);

    kfree(buf);
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
		   uint64_t phys_addr, uint64_t lin_addr, char **memwithStrings, 
		   uint64_t rax, uint64_t rbx, uint64_t rcx, uint64_t rdx,
		   uint64_t rsi, uint64_t rdi, uint64_t r8, uint64_t r9,
		   uint64_t r10, uint64_t r11, uint64_t r12, uint64_t r13, uint64_t r14, uint64_t r15,
		   uint64_t rflags, uint64_t rsp, uint64_t rbp, uint64_t branch_target_rip)
{
	
	if (!(opData3.ld_op == 1 || opData3.st_op == 1 || opData1.op_brn_ret)) return;

	char * buf = kmalloc(1024, GFP_KERNEL);
	if (!buf)
		return;

	int n = scnprintf(
			buf, 1024,
			"0x%llx,%llu,%s%s,0x%llx,0x%llx,%s,%s,%s," 
			"%s,%s,%s,%s,%s,0x%llx,"
			"0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,"
			"0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx\n",
			rip_value, uop_cnt, opData3.ld_op ? "load" : (opData3.st_op ? "store" : "branch"),
			(opData3.ld_op || opData3.st_op) ? memwithStrings[opData3.op_mem_width] : "", phys_addr,
			lin_addr, opData3.dc_uc_mem_acc ? "True" : "False",
			opData3.dc_wc_mem_acc ? "True" : "False",
			opData3.dc_miss ? "True" : "False",
			opData1.op_microcode ? "True" : "False",
			opData1.op_brn_fuse ? "True" : "False",
			opData1.op_brn_ret ? "True" : "False",
			opData1.op_brn_misp ? "True" : "False",
			opData1.op_brn_taken ? "True" : "False",
			opData1.op_brn_ret ? branch_target_rip : 0x0,
			rax, rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
			rsp, rbp, rflags);

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
