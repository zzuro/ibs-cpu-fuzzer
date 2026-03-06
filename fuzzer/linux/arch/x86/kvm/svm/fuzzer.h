#pragma once

#include <linux/types.h>

#define MAX_INSN_LENGTH 15
#define UD2_SIZE  2
#define MAGIC_VALUE 0x1234DEADBEEF1234ULL

#define REGISTER_VALUE 			0x4000000000 
#define GUEST_PHYS_ADDR_START 	0x00400000 
#define GUEST_PHYS_ADDR_END 	0x005FFFFF
#define GUEST_PHYS_PAGE_SIZE 	((GUEST_PHYS_ADDR_END - GUEST_PHYS_ADDR_START + 1)/PAGE_SIZE)

#define MAX_CPU_COUNT 64

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

typedef struct {
	uint64_t rax;
	uint64_t rbx;
	uint64_t rcx;
	uint64_t rdx;
	uint64_t rsi;
	uint64_t rdi;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;
	uint64_t rbp;
	uint64_t rsp;
	uint64_t rflags;
} reg_state_t;

typedef struct cpu_state{

	uint8_t* fuzz_mem1_host;
	uint8_t* fuzz_mem1_guest;
	uint8_t* fuzz_mem2_host;
	uint8_t* fuzz_mem2_guest;

	inj_t inj;			 
	result_t result;
	range_t search_range; 

	fuzzing_op current_op;
	uint64_t fetch_counter;
	uint64_t per_instruction_counter;

	reg_state_t regs;
	uint64_t hpa_mapping[GUEST_PHYS_PAGE_SIZE];

	struct vmcb_save_area saved_state;

	bool file_open;

}cpu_state_t;

typedef struct fuzzer_state {

	range_t total_range;
	insn_t range_marker;
	
	cpu_state_t cpu_state[MAX_CPU_COUNT];

	bool done;

} fuzzer_state_t; 