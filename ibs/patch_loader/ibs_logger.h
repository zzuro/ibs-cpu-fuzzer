#pragma once
#include <linux/types.h>
#include <asm/amd/ibs.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>


int ibs_log_open(char *ibs_log_path);
void ibs_log_close(void);

void ibs_log_write_line(const char *line, size_t len);
void ibs_log_event(uint64_t rip_value, uint64_t uop_cnt, 
                    union ibs_op_data3 opData3,
                    union ibs_op_data opData1,
                    uint64_t phys_addr, uint64_t lin_addr,
                    char **memwithStrings);
           

