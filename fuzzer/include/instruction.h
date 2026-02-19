#pragma once
#include <stdint.h>
#include <stdbool.h>

#define MAX_INSN_LENGTH 15

typedef struct {
	uint8_t bytes[MAX_INSN_LENGTH];
	int len; /* the number of specified bytes in the instruction */
} insn_t;

typedef struct {
	insn_t i;       //current instruction being mutated
	int index;      //byte index being mutated
	int last_len;   //length of the last instruction, used to detect when the instruction length changes after mutation
} inj_t;

typedef struct { insn_t start; insn_t end; bool started; } range_t;


typedef struct __attribute__ ((packed)) {
	uint32_t valid;
	uint32_t length;
	uint32_t signum;
	uint32_t si_code;
	uint32_t addr;
} result_t;
