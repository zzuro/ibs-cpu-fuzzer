#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/relay.h>
#include <linux/debugfs.h>
#include <linux/preempt.h>
#include <linux/smp.h>

#include "svm.h"
#include "ibs_logger.h"

#define IBS_MAX_CPUS 32

static struct rchan *ibs_chan[IBS_MAX_CPUS];
static struct dentry *ibs_dbg_dir[IBS_MAX_CPUS];
static struct dentry *ibs_root_dir;

static atomic64_t ack_counter[IBS_MAX_CPUS];

static __always_inline uint64_t __read_msr(uint32_t msr_register)
{
	uint64_t msr_value;
	uint32_t low, high;

	asm volatile(
		"rdmsr"
		: "=a"(low), "=d"(high)
		: "c"(msr_register)
	);

	msr_value = ((uint64_t)high << 32) | low;
	return msr_value;
}

static __always_inline int ibs_this_cpu(void)
{
	int cpu;
	cpu = smp_processor_id();

	if (cpu < 0 || cpu >= IBS_MAX_CPUS)
		return -1;

	return cpu;
}

static struct dentry *ibs_create_buf_file(const char *filename,
					  struct dentry *parent,
					  umode_t mode,
					  struct rchan_buf *buf,
					  int *is_global)
{
	*is_global = 0;
	return debugfs_create_file(filename, mode, parent, buf,
				   &relay_file_operations);
}

static int ibs_remove_buf_file(struct dentry *dentry)
{
	debugfs_remove(dentry);
	return 0;
}

static struct rchan_callbacks ibs_relay_callbacks = {
	.create_buf_file = ibs_create_buf_file,
	.remove_buf_file = ibs_remove_buf_file,
};

void set_ack_event(uint64_t value)
{
	int cpu = ibs_this_cpu();
	if (cpu < 0)
		return;
	atomic64_set(&ack_counter[cpu], value);
}

uint64_t get_ack_event(void)
{
	int cpu = ibs_this_cpu();
	if (cpu < 0)
		return -1;

	return atomic64_read(&ack_counter[cpu]);
}

static __always_inline void ibs_relay_write_cpu(int cpu, const void *data, size_t len)
{
	if (cpu < 0 || cpu >= IBS_MAX_CPUS || !data || !len)
		return;

	if (!ibs_chan[cpu])
		return;

	relay_write(ibs_chan[cpu], data, len);
}

int ibs_log_open(void)
{
	int cpu;
	char name[16];

	if (ibs_root_dir)
		return 0;

	for (cpu = 0; cpu < IBS_MAX_CPUS; cpu++) {
		ibs_chan[cpu] = NULL;
		ibs_dbg_dir[cpu] = NULL;
	}

	ibs_root_dir = debugfs_create_dir(IBS_RELAY_DIR, NULL);
	if (IS_ERR_OR_NULL(ibs_root_dir)) {
		pr_err("ibs: failed to create root debugfs dir\n");
		ibs_root_dir = NULL;
		return -ENOMEM;
	}

	for (cpu = 0; cpu < IBS_MAX_CPUS; cpu++) {
		snprintf(name, sizeof(name), "cpu%d", cpu);

		ibs_dbg_dir[cpu] = debugfs_create_dir(name, ibs_root_dir);
		if (IS_ERR_OR_NULL(ibs_dbg_dir[cpu])) {
			pr_err("ibs: failed to create debugfs dir for cpu %d\n", cpu);
			ibs_dbg_dir[cpu] = NULL;
			goto err;
		}

		ibs_chan[cpu] = relay_open(IBS_RELAY_BASENAME,
					   ibs_dbg_dir[cpu],
					   IBS_SUBBUF_SIZE,
					   IBS_N_SUBBUFS,
					   &ibs_relay_callbacks,
					   NULL);
		if (!ibs_chan[cpu]) {
			pr_err("ibs: relay_open failed for cpu %d\n", cpu);
			goto err;
		}

		atomic64_set(&ack_counter[cpu], 0);
	}

	pr_info("ibs: relay binary logging enabled at /sys/kernel/debug/%s/cpu*/\n",
		IBS_RELAY_DIR);
	return 0;

err:
	for (cpu = 0; cpu < IBS_MAX_CPUS; cpu++) {
		if (ibs_chan[cpu]) {
			relay_close(ibs_chan[cpu]);
			ibs_chan[cpu] = NULL;
		}
	}

	if (ibs_root_dir) {
		debugfs_remove_recursive(ibs_root_dir);
		ibs_root_dir = NULL;
	}

	for (cpu = 0; cpu < IBS_MAX_CPUS; cpu++)
		ibs_dbg_dir[cpu] = NULL;

	return -ENOMEM;
}

void ibs_log_hpa(uint64_t *hpa, size_t len, uint8_t *raw_instr, size_t raw_instr_len)
{
	size_t i;
	int cpu;

	if (!hpa)
		return;

	cpu = ibs_this_cpu();
	if (cpu < 0 || !ibs_chan[cpu])
		return;

	for (i = 0; i < len; i++) {
		struct ibs_hpa_record rec = {
			.hdr = {
				.record_type = IBS_REC_HPA,
				.record_len = 0,
				.instruction_len = raw_instr_len,
				.instruction = {0},
			},
			.hpa = hpa[i],
		};

		memcpy(rec.hdr.instruction, raw_instr, raw_instr_len);
		rec.hdr.record_len = sizeof(rec);
		ibs_relay_write_cpu(cpu, &rec, sizeof(rec));
	}

	{
		struct ibs_hpa_record rec = {
			.hdr = {
				.record_type = IBS_REC_HPA,
				.record_len = 0,
				.instruction_len = raw_instr_len,
				.instruction = {0},
			},
			.hpa = __read_msr(0xC0010117), /* HSAVE_PA */
		};

		memcpy(rec.hdr.instruction, raw_instr, raw_instr_len);
		rec.hdr.record_len = sizeof(rec);
		ibs_relay_write_cpu(cpu, &rec, sizeof(rec));
	}
}

void ibs_log_finish(void)
{
	struct ibs_record_header rec = {
		.record_type = IBS_REC_FINISH,
		.record_len = 0,
		.instruction_len = 0,
		.instruction = {0},
	};
	int cpu;

	rec.record_len = sizeof(rec);

	cpu = ibs_this_cpu();
	if (cpu < 0 || !ibs_chan[cpu])
		return;

	ibs_relay_write_cpu(cpu, &rec, sizeof(rec));
}

void ibs_log_close(void)
{
	int cpu;

	for (cpu = 0; cpu < IBS_MAX_CPUS; cpu++) {
		if (ibs_chan[cpu]) {
			relay_flush(ibs_chan[cpu]);
			relay_close(ibs_chan[cpu]);
			ibs_chan[cpu] = NULL;
		}
	}

	if (ibs_root_dir) {
		debugfs_remove_recursive(ibs_root_dir);
		ibs_root_dir = NULL;
	}

	for (cpu = 0; cpu < IBS_MAX_CPUS; cpu++)
		ibs_dbg_dir[cpu] = NULL;
}

void ibs_log_event(uint64_t rip_value, uint64_t uop_cnt,
		   union ibs_op_data3 opData3, union ibs_op_data opData1,
		   uint64_t phys_addr, uint64_t lin_addr,
		   uint64_t rax, uint64_t rbx, uint64_t rcx, uint64_t rdx,
		   uint64_t rsi, uint64_t rdi, uint64_t r8, uint64_t r9,
		   uint64_t r10, uint64_t r11, uint64_t r12, uint64_t r13,
		   uint64_t r14, uint64_t r15,
		   uint64_t rflags, uint64_t rsp, uint64_t rbp,
		   uint64_t branch_target_rip, uint8_t *raw_instr, size_t raw_instr_len)
{
	struct ibs_event_record rec;
	int cpu;

	if (!(opData3.ld_op == 1 || opData3.st_op == 1 || opData1.op_brn_ret))
		return;

	cpu = ibs_this_cpu();
	if (cpu < 0 || !ibs_chan[cpu])
		return;

	memset(&rec, 0, sizeof(rec));

	rec.hdr.record_type = IBS_REC_EVENT;
	rec.hdr.record_len = sizeof(rec);
	rec.hdr.instruction_len = raw_instr_len;
	memcpy(rec.hdr.instruction, raw_instr, raw_instr_len);

	rec.rip = rip_value;
	rec.uop_cnt = uop_cnt;

	rec.phys_addr = phys_addr;
	rec.lin_addr = lin_addr;
	rec.branch_target_rip = opData1.op_brn_ret ? branch_target_rip : 0;

	rec.rax = rax;
	rec.rbx = rbx;
	rec.rcx = rcx;
	rec.rdx = rdx;
	rec.rsi = rsi;
	rec.rdi = rdi;
	rec.r8  = r8;
	rec.r9  = r9;
	rec.r10 = r10;
	rec.r11 = r11;
	rec.r12 = r12;
	rec.r13 = r13;
	rec.r14 = r14;
	rec.r15 = r15;
	rec.rsp = rsp;
	rec.rbp = rbp;
	rec.rflags = rflags;

	if (opData3.ld_op)
		rec.op_type = IBS_OP_LOAD;
	else if (opData3.st_op)
		rec.op_type = IBS_OP_STORE;
	else
		rec.op_type = IBS_OP_BRANCH;

	rec.mem_width = opData3.op_mem_width;

	rec.dc_uc_mem_acc = !!opData3.dc_uc_mem_acc;
	rec.dc_wc_mem_acc = !!opData3.dc_wc_mem_acc;
	rec.dc_miss       = !!opData3.dc_miss;

	rec.op_microcode  = !!opData1.op_microcode;
	rec.op_brn_fuse   = !!opData1.op_brn_fuse;
	rec.op_brn_ret    = !!opData1.op_brn_ret;
	rec.op_brn_misp   = !!opData1.op_brn_misp;
	rec.op_brn_taken  = !!opData1.op_brn_taken;

	ibs_relay_write_cpu(cpu, &rec, sizeof(rec));
}