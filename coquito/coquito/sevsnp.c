#include "sevsnp.h"
#include "ktypes.h"
#include "paging.h"
#include "interrupts.h"


#include <stddef.h>


static GHCB_page_t* system_ghcb = NULL;
static CAA_page_t* system_caa = NULL;
static CPUID_page_t* system_cpuid = NULL;


/**
    @note See section 4.1.6 "Page State Change" in the GHCB standardization document
*/
struct __attribute__((packed)) GHCB_page_state_change{
    struct __attribute__((packed)) {
        u16 cur_entry;
        u16 end_entry;  // index of last entry, inclusive
        u32 reserved;
    } GHCB_page_state_change_header;

    struct __attribute__((packed)) {
        u64 current_page: 12;
        u64 guest_frame_number: 40;
        u64 operation: 4;
        u64 is_2MiB: 1;
        u64 _zero: 7;
    } GHCB_page_state_change_entry[];
};
typedef struct GHCB_page_state_change GHCB_page_state_change_t;

enum GHCB_page_state_change_new_state {
    GHCB_PAGE_STATE_CHANGE_PAGE_PRIVATE = 0x01,
    GHCB_PAGE_STATE_CHANGE_PAGE_SHARED = 0x02,
    GHCB_PAGE_STATE_CHANGE_HINT_PSMASH = 0x03,
    GHCB_PAGE_STATE_CHANGE_HINT_UNSMASH = 0x04
};



static void ghcb__vmgexit(GHCB_page_t* ghcb, u64 exitcode, u64 exitinfo1, u64 exitinfo2);

union ghcb__msr_command {
    struct {
        u64 info: 12;
        u64 data: 52;  
    } structured;
    u64 raw;
};

FORCED_INLINE static void vmgexit(void){
    // See https://edk2.groups.io/g/devel/message/63918
    interrupts__cli();
    __asm__ volatile("cli; rep; vmmcall; sti;");
    interrupts__sti();
}

static void __attribute__((unused)) write_msr(u32 msr, u64 value){
    register u32 ecx asm("ecx") = msr;
    register u32 eax asm("eax") = (u32)(value&0xffffffff);
    register u32 edx asm("edx") = (u32)(value>>32); 

    __asm__ volatile("wrmsr" :: "r"(ecx), "r"(eax), "r"(edx));
}

static u64 __attribute__((unused)) read_msr(u32 msr){
    register u32 eax asm("eax");
    register u32 edx asm("edx");
    register u32 ecx asm("ecx") = msr;
    
    __asm__ volatile("rdmsr" : "=r"(eax), "=r"(edx): "r"(ecx));
    return (((u64)edx)<<32) | eax;
}

void sevsnp__init_hypervisor_ghcb_features(void){
    write_msr(GHCB_MSR_REG, SNP_HV_FEATURES_REQ);
    vmgexit();
    
    u64 res = read_msr(GHCB_MSR_REG);
    if( (res&0xfff) == SNP_HV_FEATURES_RESP){
        while(true){}
    }
}

void ghcb__set_system_ghcb(GHCB_page_t* ghcb){
    system_ghcb = ghcb;
}

GHCB_page_t* ghcb__get_system_ghcb(void){
    return system_ghcb;
}

void ghcb__clear_valid_bitmap(GHCB_page_t* ghcb){
    for(size_t i = 0; i < 0x10; i++){
        ghcb->valid_bitmap[i] = 0;
    }

    ghcb__set_valid_bitmap(ghcb, GHCB_VALID_BITMAP1 | GHCB_VALID_BITMAP2);
}

void ghcb__set_valid_bitmap(GHCB_page_t* ghcb, u32 fields_to_set){
    bool hasgood = false;
// See page 33 of the SEV-ES Guest-Hypervisor Communication Block Standardization
#define _GHCB_CONFIG_BITMAP(flag,ghcb_field) \
    if(fields_to_set&flag){ \
        size_t qword_offset; \
        size_t bitmap_byte_offset; \
        u8 bitmap_bit_offset; \
        qword_offset = offsetof(GHCB_page_t, ghcb_field)/8; \
        bitmap_byte_offset = qword_offset/8; \
        bitmap_bit_offset = qword_offset % 8; \
        ghcb->valid_bitmap[bitmap_byte_offset] |= 1<<bitmap_bit_offset; \
        hasgood = true; \
    }

    _GHCB_CONFIG_BITMAP(GHCB_RAX, rax);
    _GHCB_CONFIG_BITMAP(GHCB_RCX, rcx);
    _GHCB_CONFIG_BITMAP(GHCB_RDX, rdx);
    _GHCB_CONFIG_BITMAP(GHCB_RBX, rbx);

    _GHCB_CONFIG_BITMAP(GHCB_SW_EXITCODE,  sw_exitcode);
    _GHCB_CONFIG_BITMAP(GHCB_SW_EXITINFO1, sw_exitinfo1);
    _GHCB_CONFIG_BITMAP(GHCB_SW_EXITINFO2, sw_exitinfo2);
    _GHCB_CONFIG_BITMAP(GHCB_SW_SCRATCH, sw_scratch);

    _GHCB_CONFIG_BITMAP(GHCB_PROTOCOL, protocol_version);
    _GHCB_CONFIG_BITMAP(GHCB_USAGE, ghcb_usage);
    
    _GHCB_CONFIG_BITMAP(GHCB_VALID_BITMAP1, valid_bitmap);
    _GHCB_CONFIG_BITMAP(GHCB_VALID_BITMAP2, valid_bitmap[8]);

#undef _GHCB_CONFIG_BITMAP

    /** XXX: Only there for debugging/sanity check */
    if(!hasgood){
        void __attribute__((noreturn)) (*crashfunc)(void) = NULL;
        crashfunc();
    }

}


void ghcb__register_ghcb_page(GHCB_page_t* ghcb){
    u64 ghcb_phy = virt2phys((u64)ghcb);
    union ghcb__msr_command hypervisor_req;

    // We want the Guest Frame Number, GPA = GFN << 12
    // See section 2.3.1 of the GHCB MSR protocol
    hypervisor_req.structured.data = ghcb_phy>>12;
    hypervisor_req.structured.info = SNP_REG_GHCB_GPA_REQ;

    write_msr(GHCB_MSR_REG, hypervisor_req.raw);
    vmgexit();

    union ghcb__msr_command hypervisor_res;
    hypervisor_res.raw = read_msr(GHCB_MSR_REG);
    
    if( ((hypervisor_res.structured.info) != SNP_REG_GHCB_GPA_RESP) | ((hypervisor_res.structured.data) != (ghcb_phy>>12))){
        void (*t)(void) = (void*)(((u64)(hypervisor_res.structured.info))<<12);
        t();
        // Something bad happened, TODO signal it...
    } else {
        // All good!
    }
}

/**
    Changes the state of a page through the GHCB MSR protocol

    @param[in] gpa The guest physical address of the page which should have its state changed
    @param[in] make_shared Set to true if the page is to be made shared; set to false if it is to be made private

    @return A hypervisor-returned error code. Any non-zero value indicates a failure. 
*/
u32 ghcb__page_state_change(physaddr_t gpa, bool make_shared){
    {
        union ghcb__msr_command page_state_change_req;
        page_state_change_req.structured.data = (((make_shared ? 2UL : 1UL)<<52) | gpa) >> 12;
        page_state_change_req.structured.info = SNP_STATE_CHANGE_REQ;

        write_msr(GHCB_MSR_REG, page_state_change_req.raw);
        vmgexit();
    }

    union ghcb__msr_command page_state_change_res;
    page_state_change_res.raw = read_msr(GHCB_MSR_REG);

    return (page_state_change_res.raw>>32);
}

void ghcb__pio_out_with_size(GHCB_page_t* ghcb, u8 size, u16 port, u64 value){
    ghcb__clear_valid_bitmap(ghcb);

    ghcb->rax = value;
    ghcb__set_valid_bitmap(ghcb, GHCB_RAX);

    u64 exitinfo1 = 0;

    switch(size){
        case 8:
            exitinfo1 = 1<<4;
            break;
        case 16:
            exitinfo1 = 1<<5;
            break;
        case 32:
            exitinfo1 = 1<<6;
            break;
        default:    /* TODO: Trigger a crash instead, or at least return an error */
            exitinfo1 = 0;
            break;   
    }
    exitinfo1 |= (port << 16);

    /* exitinfo2 = 0: no string repetitions */
    ghcb__vmgexit(ghcb, GHCB_EXIT_CODE_IOIO_PROT, exitinfo1, 0); 

}

u64 ghcb__pio_in_with_size(GHCB_page_t* ghcb, u8 size, u16 port){
    ghcb__clear_valid_bitmap(ghcb);

    u64 exitinfo1 = 1;  // for in

    switch(size){
        case 8:
            exitinfo1 |= 1<<4;
            break;
        case 16:
            exitinfo1 |= 1<<5;
            break;
        case 32:
            exitinfo1 |= 1<<6;
            break;
        default:    /* TODO: Trigger a crash instead, or at least return an error */
            exitinfo1 = 0;
            break;   
    }
    exitinfo1 |= (port << 16);
    ghcb__vmgexit(ghcb, GHCB_EXIT_CODE_IOIO_PROT, exitinfo1, 0); 

    // TODO: Check that rax is valid
    return ghcb->rax;
}

/* bool ghcb__change_page_state(GHCB_page_t* ghcb, physaddr_t gpa, u32 page_size, bool make_shared){
    
    // Incorrect page size
    if(page_size != 4<<10 && page_size != 2<<20){
        return false;
    }

    ghcb->sw_scratch = virt2phys((virtaddr_t)(&(ghcb->shared_bufer)));

    GHCB_page_state_change_t* page_state_change = (void*)(ghcb->shared_bufer);

    page_state_change->GHCB_page_state_change_header.reserved = 0;
    page_state_change->GHCB_page_state_change_header.cur_entry = 0;
    page_state_change->GHCB_page_state_change_header.end_entry = 0;

    page_state_change->GHCB_page_state_change_entry[0]._zero = 0;
    page_state_change->GHCB_page_state_change_entry[0].is_2MiB = (page_size == 2<<20);
    page_state_change->GHCB_page_state_change_entry[0].operation = (make_shared ? GHCB_PAGE_STATE_CHANGE_PAGE_SHARED : GHCB_PAGE_STATE_CHANGE_PAGE_PRIVATE);
    page_state_change->GHCB_page_state_change_entry[0].current_page = 0;   // TODO: what should it be for a 2MiB page?
    page_state_change->GHCB_page_state_change_entry[0].guest_frame_number = gpa>>12; 

    // Not done implementing! Replace by the MSR protocol equivalent

    return 0;
} */



static void ghcb__vmgexit(GHCB_page_t* ghcb, u64 exitcode, u64 exitinfo1, u64 exitinfo2){
    (void)exitcode;

    ghcb->ghcb_usage = 0;
    ghcb->protocol_version = 2;
    ghcb__set_valid_bitmap(ghcb, GHCB_USAGE | GHCB_PROTOCOL);

    ghcb->sw_exitcode = exitcode;
    ghcb->sw_exitinfo1 = exitinfo1;
    ghcb->sw_exitinfo2 = exitinfo2;
    ghcb__set_valid_bitmap(ghcb, GHCB_SW_EXITCODE | GHCB_SW_EXITINFO2 | GHCB_SW_EXITINFO1);

    physaddr_t ghcb_phy = virt2phys((u64)ghcb);
    write_msr(GHCB_MSR_REG, ghcb_phy);
    vmgexit();

    ghcb->sw_exitinfo1 = 0;
    ghcb->sw_exitinfo2 = 0;
    // TODO: Add check to verify that no error happened
}


void caa__set_system_caa(CAA_page_t* caa){
    system_caa = caa;
}

CAA_page_t* caa__get_system_caa(void){
    return system_caa;
}


CAA_result_t caa__call(CAA_page_t* caa, enum CAA_protocol proto, union CAA_SVSM_command command, u64 rcx_val, u64 rdx_val, u64 r8_val){
    register u64 rax asm("rax");
    register u64 rcx asm("rcx");
    register u64 rdx asm("rdx");
    register u64 r8  asm("r8");
    
    /** TODO: Atomic swap and clear the field as instructed in the documetation
        For now it's not an issue as the SVSM should clear it, and we only perform
        calls to unstall the cooperative multitasking on the SVSM's part: we do not
        rely on the call's result (or even whether it was carried out at all).
     */
    
    /**
        TODO: Suspend interrupts? (vmgexit() already does it, but what about writing the MSR?)
    */

    
    /* Modify RAX and RCX after all function call; they might get trashed if modifed before !!!  */
    write_msr(GHCB_MSR_REG, SNP_RUN_VMPL_REQ | ((u64)SVSM_VMPL)<<32);
    rcx = rcx_val;
    rax = ((u64)proto&0xffffffff) << 32;
    rax |= (((u64)command.value)&0xffffffff);
    r8 = r8_val;

    caa->svsm_call_pending = 1;
    rdx = rdx_val;
    vmgexit();

    CAA_result_t res;
    res.code = rax;
    res.rcx = rcx;
    // Used to remove the "unused code" warning from GCC
    res.rdx = rdx;
    res.r8 = r8;

    return res;
}


u32 svsm__pvalidate(CAA_page_t* caa, physaddr_t gpa, bool make_valid, bool is_2MiB_page, bool ignore_unchanged){
    /* struct __attribute__((packed)) pvalidate_command {
        struct __attribute__((packed)) {
            u16 n_entries;
            u16 next_entry_idx;
            u32 reserved;
        } pvalidate_header;

        struct __attribute__((packed)) {
            u64 page_size: 2;
            u64 make_valid: 1;
            u64 ignore_eflags_cf: 1;
            u64 reserved: 8;
            u64 gfn: 52;
        } pvalidate_entry[];
    }; */

    // The struct must be 8-byte aligned
    struct __attribute__((packed,aligned(8))) pvalidate_single_command {
        struct __attribute__((packed)) {
            u16 n_entries;
            u16 next_entry_idx;
            u32 reserved;
        } pvalidate_header;

        struct __attribute__((packed)) {
            u64 page_size: 2;
            u64 make_valid: 1;
            u64 ignore_eflags_cf: 1;
            u64 reserved: 8;
            u64 gfn: 52;
        } pvalidate_entry;
    };


    struct pvalidate_single_command cmd;
    cmd.pvalidate_header.n_entries = 1;
    cmd.pvalidate_header.next_entry_idx = 0;
    cmd.pvalidate_entry.page_size = is_2MiB_page ? 1 : 0;
    cmd.pvalidate_entry.make_valid = make_valid ? 1 : 0;
    cmd.pvalidate_entry.ignore_eflags_cf = ignore_unchanged ? 1 : 0;
    cmd.pvalidate_entry.gfn = gpa>>12;

    CAA_result_t res = caa__call(caa, CAA_PROTOCOL_CORE, (union CAA_SVSM_command){.core = CAA_SVSM_CORE_PVALIDATE}, virt2phys((virtaddr_t)(&cmd)), 0, 0);
    return res.code;
}

// Has to be called on the main CPU (the core that ran the kernel code first)
void svsm__signal_boot_done(CAA_page_t* caa) {
    caa__call(caa, CAA_PROTOCOL_CORE, (union CAA_SVSM_command){.core = CAA_SVSM_NONSTANDARD_CORE_NOTIFY_BOOT_DONE}, 0, 0, 0);
}

/**
  @return A `multicoquito__tunnel_t`. If len is 0, then start indicates an error. 
*/
multicoquito__tunnel_t svsm__create_tunnel(CAA_page_t* caa, u32 peer_subguest, physaddr_t gpa_hint, size_t len) {
    multicoquito__tunnel_t res = {
        .len = 0,
        .start = 0
    };

    if (len % 4096 != 0) {
        return res; 
    }

    CAA_result_t tunnel_result = caa__call(
        caa,
        CAA_PROTOCOL_CORE,
        (union CAA_SVSM_command){.core = CAA_SVSM_NONSTANDARD_CORE_CREATE_TUNNEL},
        gpa_hint,
        peer_subguest,
        len / 4096);
    
    if(tunnel_result.code == 0){
        // The SVSM expresses the tunnel length in multiples of standard pages,
        // whereas we want bytes.
        res.len = tunnel_result.r8*4096;
        res.start = tunnel_result.rcx;
    } else {
        res.len = 0;
        res.start = tunnel_result.code;
    }

    return res;
}


u32 svsm__reclaim_tunnel(CAA_page_t* caa, physaddr_t tunnel_gpa) {
    CAA_result_t res = caa__call(
        caa,
        CAA_PROTOCOL_CORE,
        (union CAA_SVSM_command){.core = CAA_SVSM_NONSTANDARD_CORE_RECLAIM_TUNNEL},
        tunnel_gpa,
        0,
        0);
    
    return res.code;
}

u32 svsm__benchmarking_start(CAA_page_t* caa) {
    CAA_result_t res = caa__call(
        caa,
        CAA_PROTOCOL_CORE, 
        (union CAA_SVSM_command){.core = CAA_SVSM_NONSTANDARD_CORE_START_RECORDING_PERFORMANCES}, 
        (u64)0, 
        0UL,
        0);

    return res.code;
}


u32 svsm__benchmarking_stop(CAA_page_t* caa) {
    CAA_result_t res = caa__call(
        caa,
        CAA_PROTOCOL_CORE, 
        (union CAA_SVSM_command){.core = CAA_SVSM_NONSTANDARD_CORE_STOP_RECORDING_PERFORMANCES}, 
        (u64)0, 
        0UL,
        0);

    return res.code;
}


u32 svsm__benchmarking_flush(CAA_page_t* caa) {
    CAA_result_t res = caa__call(
        caa,
        CAA_PROTOCOL_CORE, 
        (union CAA_SVSM_command){.core = CAA_SVSM_NONSTANDARD_CORE_FLUSH_PERFORMANCES}, 
        (u64)0, 
        0UL,
        0);

    return res.code;
}


u32 svsm__benchmarking_set_label(CAA_page_t* caa, u64 label) {
    CAA_result_t res = caa__call(
        caa,
        CAA_PROTOCOL_CORE, 
        (union CAA_SVSM_command){.core = CAA_SVSM_NONSTANDARD_CORE_SET_BENCHMARKING_LABEL}, 
        label, 
        0UL,
        0);

    return res.code;
}


u32 svsm__benchmarking_unset_label(CAA_page_t* caa) {
    CAA_result_t res = caa__call(
        caa,
        CAA_PROTOCOL_CORE, 
        (union CAA_SVSM_command){.core = CAA_SVSM_NONSTANDARD_CORE_UNSET_BENCHMARKING_LABEL}, 
        (u64)0, 
        0UL,
        0);

    return res.code;
}


void svsm__dummy_caa_call(CAA_page_t* caa) {
    caa__call(
        caa,
        CAA_PROTOCOL_CORE,
        (union CAA_SVSM_command){.core = CAA_SVSM_CORE_QUERY_PROTOCOL},
        (u64)0,
        0UL,
        0);
}



union sevsnp__rmpadjust_result sevsnp__rmpadjust(virtaddr_t target_page, bool is_2MiB_page, u8 target_vmpl, u8 permission_mask) {
    u64 rdx_val, rcx_val;

    rdx_val = target_vmpl | (((u32)permission_mask) << 8);
    rcx_val = is_2MiB_page;  // 4KiB page ==> 0

    union sevsnp__rmpadjust_result res;

    __asm__ volatile(
        "movq %1, %%rax\n\t"
        "movq %2, %%rdx\n\t"
        "movq %3, %%rcx\n\t"
        ".byte 0xf3, 0x0f, 0x01, 0xfe\n\t"
        "mov %%eax, %0\n\t"
        : "=r"(res.code)
        : "r"(target_page), "r"(rdx_val), "r"(rcx_val)
        : "cc", "rax", "rdx", "rcx"
    );

    return res;
}


void cpuid__set_system_cpuid(CPUID_page_t* cpuid){
    system_cpuid = cpuid;
}

CPUID_page_t* cpuid__get_system_cpuid(void){
    return system_cpuid;
}
