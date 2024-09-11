#pragma once

#include <memory.h>
#include <HYPEREYE_defs.h>
#include <stddef.h>

#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/kfifo.h>
#include <linux/hashtable.h>

typedef struct internal_guest internal_guest;
typedef struct internal_vcpu internal_vcpu;
typedef struct internal_memory_region internal_memory_region;
typedef struct internal_mmu internal_mmu;

#define MAX_NUM_GUESTS          16
#define MAX_NUM_VCPUS           16
#define MAX_NUM_MEM_REGIONS     128

extern internal_guest*          g_guests[MAX_NUM_GUESTS];
extern internal_guest           kvm_guest; // Created if we decided to trace a KVM guest

struct internal_guest {
    uint64_t                    id;
    void*                       arch_internal_guest; // will be casted to a arch-dependent guest type
    internal_memory_region*	    memory_regions[MAX_NUM_MEM_REGIONS];
    internal_vcpu*              vcpus[MAX_NUM_VCPUS];
    struct rw_semaphore         vcpu_lock;
    internal_mmu*               mmu;
    uint64_t*                   fuzzing_coverage;
    uint64_t                    fuzzing_coverage_size;
    DECLARE_HASHTABLE           (breakpoints, 7); // uses virtual breakpoint addresses as keys
    uint64_t                    breakpoints_cnt;
} typedef internal_guest;

// Functions assume guest_list_lock to be locked.
internal_guest* create_guest(void);
internal_guest* simple_copy_guest(internal_guest *g);
void            destroy_guest(internal_guest *g);
void            destroy_all_guests(void);
internal_vcpu*  create_vcpu(internal_guest *g);
void            destroy_vcpu(internal_vcpu *vcpu);
internal_guest* map_guest_id_to_guest(uint64_t id);
int             insert_new_guest(internal_guest *g);
int             remove_guest(internal_guest *g);

void guest_list_lock(void);
void guest_list_unlock(void);
void guest_vcpu_read_lock(internal_guest *g);
void guest_vcpu_read_unlock(internal_guest *g);
void guest_vcpu_write_lock(internal_guest *g);
void guest_vcpu_write_unlock(internal_guest *g);

struct internal_breakpoint {
    // Breakpoints can be set on either guest virtual of phyiscal addresses.
    // In case only the physical address is set, the virtual one will be
    // calculated the first time the breakpoint is hit.
    gva_t                       guest_addr_v;
    gpa_t                       guest_addr_p;
    uint64_t                    old_mem;
    uint64_t                    num;
    struct hlist_node           hlist;
} typedef internal_breakpoint;

internal_breakpoint* find_breakpoint_by_gpa(internal_guest *g, gpa_t guest_addr);
internal_breakpoint* find_breakpoint_by_gva(internal_guest *g, gva_t guest_addr);
void insert_breakpoint(internal_guest *g, internal_breakpoint *bp);
void remove_breakpoint(internal_guest *g, internal_breakpoint *bp);
void destroy_all_breakpoints(internal_guest *g); // will be called upon guest destruction

enum vcpu_state {VCPU_STATE_CREATED, VCPU_STATE_RUNNING, VCPU_STATE_PAUSED, VCPU_STATE_FAILED, VCPU_STATE_DESTROYED, VCPU_STATE_SINGLESTEP, VCPU_STATE_BREAKPOINT} typedef vcpu_state;

struct internal_vcpu {
    uint64_t                    id;
    vcpu_state		            state;
    uint64_t                    physical_core;
    void*                       arch_internal_vcpu; // will be casted to a arch-dependent guest type
} typedef internal_vcpu;

// Functions assume guest_lock to be locked.
internal_vcpu* 	map_vcpu_id_to_vcpu(uint64_t id, internal_guest *g);
int             insert_new_vcpu(internal_vcpu* vcpu, internal_guest *g);
int             remove_vcpu(internal_vcpu *vcpu, internal_guest *g);
void            for_every_vcpu(internal_guest *g, void(*callback)(internal_vcpu*, void*), void *arg);

// An abstraction for all functions provided by an hypervisor implementation.
struct internal_HYPEREYE_ops {
    // Managing guests/VCPUs
    int         (*run_vcpu)(internal_vcpu*, internal_guest*);
    void*       (*create_arch_internal_vcpu)(internal_guest*, internal_vcpu*);
    void*       (*simple_copy_arch_internal_vcpu)(internal_guest*, internal_vcpu*, internal_vcpu*);
    int         (*destroy_arch_internal_vcpu)(internal_vcpu*);

    void*       (*create_arch_internal_guest) (internal_guest*);
    void*       (*simple_copy_arch_internal_guest)(internal_guest*, internal_guest*);
    void        (*destroy_arch_internal_guest)(internal_guest*);
    // Managing guest/VCPU state
    void        (*set_vcpu_registers)(internal_vcpu*, user_arg_registers*);
    void        (*get_vcpu_registers)(internal_vcpu*, user_arg_registers*);
    void        (*set_memory_region) (internal_guest*, internal_memory_region*);

    // MMU-related functions
    uint64_t    (*map_page_attributes_to_arch) (uint64_t);      // map arch-independent flags to architecture flags
    uint64_t    (*map_arch_to_page_attributes) (uint64_t);      // map architecture flags to arch-independent flags
    void        (*init_mmu) (internal_mmu*);
    void        (*destroy_mmu) (internal_mmu*);
    int         (*mmu_walk_available) (hpa_t*, gpa_t, unsigned int*);
    hpa_t*      (*mmu_walk_next) (hpa_t*, gpa_t, unsigned int*);
    hpa_t*      (*mmu_walk_init) (internal_mmu*, gpa_t, unsigned int*);
    gpa_t       (*mmu_gva_to_gpa) (internal_guest*, gva_t);

    // Breakpoints
    int         (*add_breakpoint_p)(internal_guest*, gpa_t);
    int         (*add_breakpoint_v)(internal_guest*, gva_t);
    int         (*remove_breakpoint)(internal_guest*, internal_vcpu*, internal_breakpoint *bp);
    int         (*singlestep)(internal_guest* g, internal_vcpu* vcpu);

    // I/O handlers
    void        (*handle_mmio)(internal_vcpu*, gpa_t, int);

    // KVM-realted functions
    void        (*register_kvm_record_handler)(void);
    void        (*deregister_kvm_record_handler)(void);
} typedef internal_HYPEREYE_ops;

extern internal_HYPEREYE_ops HYPEREYE_ops;