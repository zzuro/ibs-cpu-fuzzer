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

void ibs_trace_emit(u64 rip_value, u64 uop_cnt, u64 phys_addr, u64 lin_addr,
		    union ibs_op_data3 opData3, union ibs_op_data opData1);

void ibs_trace_start(insn_t *insn);
void ibs_trace_finished(insn_t *insn);


int ibs_log_open(char *ibs_log_path);
void ibs_log_close(void);

void ibs_log_write_line(const char *line, size_t len);
void ibs_log_event(uint64_t rip_value, uint64_t uop_cnt, 
                    union ibs_op_data3 opData3,
                    union ibs_op_data opData1,
                    uint64_t phys_addr, uint64_t lin_addr,
                    char **memwithStrings);


char *ibs_generate_filename(const u8 *bytes, size_t len);              


