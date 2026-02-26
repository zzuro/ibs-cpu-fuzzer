#pragma once

#include "ktypes.h"

#define GHCB_MSR_REG 0xC0010130
#define SVSM_VMPL 0

enum GHCB_MSR_PROTO_COMMANDS {
    SEV_INFO_REQ = 0x02,
    SEV_INFO_RESP = 0x01,
    SNP_REG_GHCB_GPA_REQ = 0x12,
    SNP_REG_GHCB_GPA_RESP = 0x13,
    SNP_STATE_CHANGE_REQ = 0x14,
    SNP_STATE_CHANGE_RESP = 0x15,
    SNP_RUN_VMPL_REQ = 0x16,
    SNP_RUN_VMPL_RESP = 0x17,
    SNP_HV_FEATURES_REQ = 0x80,
    SNP_HV_FEATURES_RESP = 0x81,
    TERM_REQ = 0x100
};

/**
    Layout of a Guest-Host Communication Block

    See     SEV-ES Guest-Hypervisor Communication Block Standardization (AMD publication #56421)
            pages 25-27
*/
struct __attribute__((packed)) GHCB_page {
    u8 _reserved1[0xcb];
    u8 cpl;
    u8 _reserved2[0x74];
    u64 xss;
    u8 _reserved3[0x18];
    u64 dr7;
    u8 _reserved4[0x90];
    u64 rax;
    u8 _reserved5[0x100];
    u8 _reserved6[0x08];
    u64 rcx;
    u64 rdx;
    u64 rbx;
    u8 _reserved7[0x70];
    u64 sw_exitcode;
    u64 sw_exitinfo1;
    u64 sw_exitinfo2;
    u64 sw_scratch;
    u8 _reserved8[0x38];
    u64 xcr0;
    u8 valid_bitmap[0x10];
    //u64 valid_bitmap[0x2];
    u64 x87_state_gpa;
    u8 _reserved9[0x3f8];
    u8 shared_bufer[0x7f0];
    u8 _reserved11[0x0a];

    /** should be either either 1 or 2 */
    u16 protocol_version;
    
    /** should be 0 */
    u32 ghcb_usage;        
};
typedef struct GHCB_page GHCB_page_t;

struct CAA_page {
    u8 svsm_call_pending;
    u8 svsm_mem_available;
    u8 _reserved[8];
};
typedef struct CAA_page CAA_page_t;

enum CAA_protocol {
    CAA_PROTOCOL_CORE = 0,
    CAA_PROTOCOL_ATTESTATION = 1,
    CAA_PROTOCOL_VTPM = 2
};

enum CAA_return_code {
    CAA_SVSM_SUCCESS = 0,
    CAA_SVSM_ERR_MORE_MEM_START = 0x40000000, 
    CAA_SVSM_ERR_MORE_MEM_END = 0x7fffffff,
    CAA_SVSM_ERR_INCOMPLETE = 0x80000000,
    CAA_SVSM_ERR_UNSUPPORTED_PROTOCOL = 0x80000001,
    CAA_SVSM_ERR_UNSUPPORTED_CALL = 0x80000002,
    CAA_SVSM_ERR_INVALID_ADDRESS = 0x80000003,
    CAA_SVSM_ERR_INVALID_FORMAT = 0x80000004,
    CAA_SVSM_ERR_INVALID_PARAMETER = 0x80000005,
    CAA_SVSM_ERR_INVALID_REQUEST = 0x80000006,
    CAA_SVSM_ERR_BUSY = 0x80000007
};

struct CAA_result {
    enum CAA_return_code code;
    u64 rcx;
    u64 rdx;
    u64 r8;
};
typedef struct CAA_result CAA_result_t;

enum CAA_SVSM_core_commands {
    CAA_SVSM_CORE_REMAP_CA = 0,
    CAA_SVSM_CORE_PVALIDATE = 1,
    CAA_SVSM_CORE_CREATE_VCPU = 2,
    CAA_SVSM_CORE_DELETE_VCPU = 3,
    CAA_SVSM_CORE_DEPOSIT_MEM = 4,
    CAA_SVSM_CORE_WITHDRAW_MEM = 5,
    CAA_SVSM_CORE_QUERY_PROTOCOL = 6,
    CAA_SVSM_CORE_CONFIGURE_VTOM = 7,
    CAA_SVSM_NONSTANDARD_CORE_NOTIFY_BOOT_DONE = 8,
    CAA_SVSM_NONSTANDARD_CORE_GET_VCPU_GROUP = 9,
    CAA_SVSM_NONSTANDARD_CORE_CREATE_TUNNEL = 10,
    CAA_SVSM_NONSTANDARD_CORE_RECLAIM_TUNNEL = 11,
    CAA_SVSM_NONSTANDARD_CORE_START_RECORDING_PERFORMANCES = 12,
    CAA_SVSM_NONSTANDARD_CORE_STOP_RECORDING_PERFORMANCES = 13,
    CAA_SVSM_NONSTANDARD_CORE_FLUSH_PERFORMANCES = 14,
    CAA_SVSM_NONSTANDARD_CORE_SET_BENCHMARKING_LABEL = 15,
    CAA_SVSM_NONSTANDARD_CORE_UNSET_BENCHMARKING_LABEL = 16
};

enum CAA_SVSM_attestation_commands {
    CAA_SVSM_ATTEST_SERVICES = 0,
    CAA_SVSM_ATTEST_SINGLE_SERVICE = 1
};

enum CAA_SVSM_vtpm_commands {
    CAA_SVSM_VTPM_QUERY = 0,
    CAA_SVSM_VTPM_CMD = 1
};

union CAA_SVSM_command {
    enum CAA_SVSM_core_commands core;
    enum CAA_SVSM_attestation_commands attestation;
    enum CAA_SVSM_vtpm_commands vtpm;
    u32 value;
};


enum GHCB_fields_to_hypervisor {
    GHCB_RAX = 1<<0,
    GHCB_RCX = 1<<1,
    GHCB_RDX = 1<<2,
    GHCB_RBX = 1<<3,
    GHCB_SW_EXITCODE  = 1<<4,
    GHCB_SW_EXITINFO1 = 1<<5,
    GHCB_SW_EXITINFO2 = 1<<6,
    GHCB_SW_SCRATCH = 1<<7,
    GHCB_PROTOCOL = 1<<8,
    GHCB_USAGE = 1<<9,

    /** The field validity bitmap need to be validated by itself 
        Pretty weird if you ask me as taking into account what it
        says is alreay considering it valid...

        This is done in the ghcb__clear_valid_bitmap function (as soon as
        the bitmap is cleared, it is validated again).

        There are 16 bytes = 2 qwords to validate, hence the two values.
    */
    GHCB_VALID_BITMAP1 = 1<<10,
    GHCB_VALID_BITMAP2 = 1<<11
};

enum GHCB_exit_codes {
    GHCB_EXIT_CODE_IOIO_PROT = 0x7b
};

/**
    @note See Table 15 of the SEV Secure Nested Paging Firmware ABI specifications
    (AMD document #56860).
*/
struct __attribute__((packed)) CPUID_page_function {
    u32 eax_in;
    u32 ecx_in;
    u64 xcr0_in;
    u64 xss_in;

    u32 eax_out;
    u32 ebx_out;
    u32 ecx_out;
    u32 edx_out;
};
// No typedef as this struct is only used internally by CPUID_page


struct multicoquito__tunnel {
    physaddr_t start;
    size_t len;
};
typedef struct multicoquito__tunnel multicoquito__tunnel_t;


#define CPUID_PAGE_COUNT_MAX 64
/**
    @note See Table 71 of the SEV Secure Nested Paging Firmware ABI specifications
    (AMD document #56860).
*/
struct __attribute__((packed)) CPUID_page {

    u32 count;  //< Must be less than or equal to CPUID_PAGE_COUNT_MAX  
    u32 _zero1; //< Must be zero
    u64 _zero2; //< Must be zero

    /** There are actually `count` functions, the rest are invalid entries */
    struct CPUID_page_function functions[CPUID_PAGE_COUNT_MAX]; 
};
typedef struct CPUID_page CPUID_page_t;


enum sevsnp__rmpadjust_permissions {
    RMPADJUST_PERM_NONE = 0,
    RMPADJUST_PERM_READ = 1,
    RMPADJUST_PERM_WRITE = 2,
    RMPADJUST_PERM_EXEC_USER = 4,
    RMPADJUST_PERM_EXEC_KERN = 8,
};

enum sevsnp__rmpadjust_result_status {
    RMPADJUST_SUCCESS = 0,
    RMPADJUST_FAIL_INPUT = 1,
    RMPADJUST_FAIL_PERMISSION = 2,
    RMPADJUST_FAIL_SIZEMISMATCH = 6,
};

union sevsnp__rmpadjust_result {
    u32 code;
    enum sevsnp__rmpadjust_result_status status;
};

void ghcb__set_system_ghcb(GHCB_page_t* ghcb);
GHCB_page_t* ghcb__get_system_ghcb(void);

void ghcb__clear_valid_bitmap(GHCB_page_t* ghcb);
void ghcb__set_valid_bitmap(GHCB_page_t* ghcb, u32 fields_to_set);  // use enum GHCB_fields_to_hypervisor to compose the fields

void ghcb__register_ghcb_page(GHCB_page_t* ghcb);
u32 ghcb__page_state_change(physaddr_t gpa, bool make_shared);
void ghcb__pio_out_with_size(GHCB_page_t* ghcb, u8 size, u16 port, u64 value);
u64 ghcb__pio_in_with_size(GHCB_page_t* ghcb, u8 size, u16 port);

void caa__set_system_caa(CAA_page_t* caa);
CAA_page_t* caa__get_system_caa(void);
CAA_result_t caa__call(CAA_page_t* caa, enum CAA_protocol proto, union CAA_SVSM_command command, u64 rcx_val, u64 rdx_val, u64 r8_val);


u32 svsm__pvalidate(CAA_page_t* caa, physaddr_t gpa, bool make_valid, bool is_2MiB_page, bool ignore_unchanged);
void svsm__signal_boot_done(CAA_page_t* caa);
multicoquito__tunnel_t svsm__create_tunnel(CAA_page_t* caa, u32 peer_subguest, physaddr_t gpa_hint, size_t len);
u32 svsm__reclaim_tunnel(CAA_page_t* caa, physaddr_t tunnel_gpa);

void svsm__dummy_caa_call(CAA_page_t* caa);

u32 svsm__benchmarking_start(CAA_page_t* caa);
u32 svsm__benchmarking_stop(CAA_page_t* caa);
u32 svsm__benchmarking_flush(CAA_page_t* caa);
u32 svsm__benchmarking_set_label(CAA_page_t* caa, u64 label);
u32 svsm__benchmarking_unset_label(CAA_page_t* caa);

void cpuid__set_system_cpuid(CPUID_page_t* cpuid);
CPUID_page_t* cpuid__get_system_cpuid(void);

void sevsnp__init_hypervisor_ghcb_features(void);
union sevsnp__rmpadjust_result sevsnp__rmpadjust(virtaddr_t target_page, bool is_2MiB_page, u8 target_vmpl, u8 permission_mask);
