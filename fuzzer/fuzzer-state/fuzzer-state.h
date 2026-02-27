#pragma once
#include <stdint.h>

#define MAX_INSN_LENGTH 15
#define UD2_SIZE  2
#define MAGIC_VALUE 0x1234DEADBEEF1234ULL

struct vmcb_seg {
	uint16_t selector;
	uint16_t attrib;
	uint32_t limit;
	uint64_t base;
} __attribute__((packed));

/* Save area definition for legacy and SEV-MEM guests */
struct vmcb_save_area {
	struct vmcb_seg es;
	struct vmcb_seg cs;
	struct vmcb_seg ss;
	struct vmcb_seg ds;
	struct vmcb_seg fs;
	struct vmcb_seg gs;
	struct vmcb_seg gdtr;
	struct vmcb_seg ldtr;
	struct vmcb_seg idtr;
	struct vmcb_seg tr;
	/* Reserved fields are named following their struct offset */
	uint8_t reserved_0xa0[42];
	uint8_t vmpl;
	uint8_t cpl;
	uint8_t reserved_0xcc[4];
	uint64_t efer;
	uint8_t reserved_0xd8[112];
	uint64_t cr4;
	uint64_t cr3;
	uint64_t cr0;
	uint64_t dr7;
	uint64_t dr6;
	uint64_t rflags;
	uint64_t rip;
	uint8_t reserved_0x180[88];
	uint64_t rsp;
	uint64_t s_cet;
	uint64_t ssp;
	uint64_t isst_addr;
	uint64_t rax;
	uint64_t star;
	uint64_t lstar;
	uint64_t cstar;
	uint64_t sfmask;
	uint64_t kernel_gs_base;
	uint64_t sysenter_cs;
	uint64_t sysenter_esp;
	uint64_t sysenter_eip;
	uint64_t cr2;
	uint8_t reserved_0x248[32];
	uint64_t g_pat;
	uint64_t dbgctl;
	uint64_t br_from;
	uint64_t br_to;
	uint64_t last_excp_from;
	uint64_t last_excp_to;
	uint8_t reserved_0x298[72];
	uint64_t spec_ctrl;		/* Guest version of SPEC_CTRL at 0x2E0 */
} __attribute__((packed));

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
	uint32_t current_length;
	result_t result;

	fuzzing_op current_op;
	uint64_t fetch_counter;

	struct vmcb_save_area saved_state;

	bool file_open;

} fuzzer_state_t; 