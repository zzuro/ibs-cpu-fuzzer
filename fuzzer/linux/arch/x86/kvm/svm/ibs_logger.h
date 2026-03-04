#pragma once
#include <linux/types.h>
#include <asm/amd/ibs.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include "fuzzer.h"


#define IBS_PREFIX "/mnt/home/avezzu/ibs_log/ibs_"
#define IBS_SUFFIX ".csv"



int ibs_log_open(char *ibs_log_path);
void ibs_log_close(void);

void ibs_log_write_line(const char *line, size_t len);
void ibs_log_event(uint64_t rip_value, uint64_t uop_cnt,
		   union ibs_op_data3 opData3, union ibs_op_data opData1,
		   uint64_t phys_addr, uint64_t lin_addr, char **memwithStrings, 
		   uint64_t rax, uint64_t rbx, uint64_t rcx, uint64_t rdx,
		   uint64_t rsi, uint64_t rdi, uint64_t r8, uint64_t r9,
		   uint64_t r10, uint64_t r11, uint64_t r12, uint64_t r13, uint64_t r14, uint64_t r15,
		   uint64_t rflags, uint64_t rsp, uint64_t rbp);


char *ibs_generate_filename(const u8 *bytes, size_t len);              


