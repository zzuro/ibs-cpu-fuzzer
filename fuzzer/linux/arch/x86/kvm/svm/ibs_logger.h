#pragma once
#include <linux/types.h>
#include <asm/amd/ibs.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include "fuzzer.h"


#define IBS_RELAY_DIR       "ibs_logger"
#define IBS_RELAY_BASENAME  "trace"
#define IBS_SUBBUF_SIZE (1024 * 1024)
#define IBS_N_SUBBUFS   8


/*
 * Record types in the relay stream.
 */
enum ibs_record_type {
	IBS_REC_INVALID = 1,
	IBS_REC_HPA	= 2,     
	IBS_REC_EVENT = 3,
	IBS_REC_FINISH = 4,   
};

/*
 * Encoded op types.
 */
enum ibs_op_type {
	IBS_OP_LOAD   = 1,
	IBS_OP_STORE  = 2,
	IBS_OP_BRANCH = 3,
};


struct ibs_record_header {
	__u32 record_type;
	__u16 record_len;
	__u16 instruction_len;    
	__u8 instruction[16]; 	
} __packed;

/*
 * HPA record.
 */
struct ibs_hpa_record {
	struct ibs_record_header hdr;
	__u64 hpa;
} __packed;

/*
 * Main binary event record.
 */
struct ibs_event_record {
	struct ibs_record_header hdr;
	__u64 rip;
	__u64 uop_cnt;

	__u64 phys_addr;
	__u64 lin_addr;
	__u64 branch_target_rip;

	__u64 rax;
	__u64 rbx;
	__u64 rcx;
	__u64 rdx;
	__u64 rsi;
	__u64 rdi;
	__u64 r8;
	__u64 r9;
	__u64 r10;
	__u64 r11;
	__u64 r12;
	__u64 r13;
	__u64 r14;
	__u64 r15;
	__u64 rsp;
	__u64 rbp;
	__u64 rflags;

	__u32 op_type;          /* enum ibs_op_type */
	__u32 mem_width;        /* raw op_mem_width */

	__u8 dc_uc_mem_acc;
	__u8 dc_wc_mem_acc;
	__u8 dc_miss;
	__u8 op_microcode;
	__u8 op_brn_fuse;
	__u8 op_brn_ret;
	__u8 op_brn_misp;
	__u8 op_brn_taken;

} __packed;




int ibs_log_open(void);
void ibs_log_close(void);

void ibs_log_hpa(uint64_t *hpa, size_t len, uint8_t *raw_instr, size_t raw_instr_len);
void ibs_log_finish(void);

void ibs_log_event(uint64_t rip_value, uint64_t uop_cnt,
		   union ibs_op_data3 opData3, union ibs_op_data opData1,
		   uint64_t phys_addr, uint64_t lin_addr,
		   uint64_t rax, uint64_t rbx, uint64_t rcx, uint64_t rdx,
		   uint64_t rsi, uint64_t rdi, uint64_t r8, uint64_t r9,
		   uint64_t r10, uint64_t r11, uint64_t r12, uint64_t r13,
		   uint64_t r14, uint64_t r15,
		   uint64_t rflags, uint64_t rsp, uint64_t rbp,
		   uint64_t branch_target_rip, uint8_t *raw_instr, size_t raw_instr_len);



void set_ack_event(uint64_t value);
uint64_t get_ack_event(void);
