#pragma once

#include <linux/types.h>

#define MAX_INSN_LENGTH 15
#define UD2_SIZE  2
#define MAGIC_VALUE 0x1234DEADBEEF1234ULL

typedef struct {
	uint8_t bytes[MAX_INSN_LENGTH];
	uint32_t len; 
} insn_t;

typedef struct {
	insn_t i;       
	int index;
	int last_len;      
} inj_t;

typedef struct { insn_t start; insn_t end; bool started; } range_t;

typedef struct __attribute__ ((packed)) {
	uint32_t valid;
	int length;
	uint32_t ecxeption;
} result_t;

typedef enum
{
    START,
    INSTRUCTION,
    MICROOP
} fuzzing_op;

typedef struct fuzzer_state {

	uint8_t* fuzz_mem1_host;
	uint8_t* fuzz_mem1_guest;
	uint8_t* fuzz_mem2_host;
	uint8_t* fuzz_mem2_guest;

	range_t total_range;
	inj_t inj;
	result_t result;

	fuzzing_op current_op;
	uint64_t fetch_counter;

	struct vmcb_save_area saved_state;

	bool file_open;

} fuzzer_state_t; 