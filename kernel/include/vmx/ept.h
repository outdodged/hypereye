#pragma once

#include <guest.h>
#include <memory.h>
#include <stddef.h>

// IA32_VMX_EPT_VPID_CAP_MSR bitfields
#define VMX_EPT_CAP_EXEC_ONLY                                   ((uint64_t)1) << 0
#define VMX_EPT_CAP_PAGE_WALK_LEN_4                             ((uint64_t)1) << 6
#define VMX_EPT_CAP_UNCACHEABLE_MEM_TYPE                        ((uint64_t)1) << 8
#define VMX_EPT_CAP_WRITEBACK_MEM_TYPE                          ((uint64_t)1) << 14
#define VMX_EPT_CAP_PDE_2MB                                     ((uint64_t)1) << 16
#define VMX_EPT_CAP_PDPTE_1GB                                   ((uint64_t)1) << 17
#define VMX_EPT_CAP_INVEPT                                      ((uint64_t)1) << 20
#define VMX_EPT_CAP_DIRTY_FLAG                                  ((uint64_t)1) << 21
#define VMX_EPT_CAP_ADVANCED_EXIT_INFO                          ((uint64_t)1) << 22
#define VMX_EPT_CAP_SUPERVISOR_SHADOW_STACK                     ((uint64_t)1) << 23
#define VMX_EPT_CAP_SINGLE_CONTEXT_INVEPT                       ((uint64_t)1) << 25
#define VMX_EPT_CAP_ALL_CONTEXT_INVEPT                          ((uint64_t)1) << 26
#define VMX_EPT_CAP_INVVPID                                     ((uint64_t)1) << 32
#define VMX_EPT_CAP_INDIVIDUAL_ADDR_INVVPID                     ((uint64_t)1) << 40
#define VMX_EPT_CAP_SINGLE_CONTEXT_INVVPID                      ((uint64_t)1) << 41
#define VMX_EPT_CAP_ALL_CONTEXT_INVVPID                         ((uint64_t)1) << 42
#define VMX_EPT_CAP_SINGLE_CONTEXT_RETAINING_GLOBALS_INVVPID    ((uint64_t)1) << 43

// Cache types
#define VMX_EPT_CACHE_MEMORY_TYPE_UC         0x0000
#define VMX_EPT_CACHE_MEMORY_TYPE_WC         0x0001
#define VMX_EPT_CACHE_MEMORY_TYPE_WT         0x0004
#define VMX_EPT_CACHE_MEMORY_TYPE_WP         0x0005
#define VMX_EPT_CACHE_MEMORY_TYPE_WB         0x0006
#define VMX_EPT_CACHE_MEMORY_TYPE_UC_MINUS   0x0007
#define VMX_EPT_CACHE_MEMORY_TYPE_ERROR      0x00FE
#define VMX_EPT_CACHE_MEMORY_TYPE_RESERVED   0x00FF

// EPT page table structures, here for a depth of 4
union ept_pml4e {
    uint64_t all;
    struct {
        uint64_t read : 1;
        uint64_t write : 1;
        uint64_t exec : 1;
        uint64_t reserved_0 : 5; // must be 0
        uint64_t access : 1;
        uint64_t reserved_1 : 1;
        uint64_t exec_user : 1;
        uint64_t reserved_2 : 2;
        uint64_t physical_addr : 36;
        uint64_t reserved_3 : 4;
        uint64_t reserved_4 : 12;
    } bits;
} typedef ept_pml4e;

union ept_pdpte {
    uint64_t all;
    struct {
        uint64_t read : 1;
        uint64_t write : 1;
        uint64_t exec : 1;
        uint64_t reserved_0 : 5;
        uint64_t access : 1;
        uint64_t reserved_1 : 1;
        uint64_t exec_user : 1;
        uint64_t reserved_2 : 2;
        uint64_t physical_addr : 36;
        uint64_t reserved_3 : 4;
        uint64_t reserved_4 : 12;
    } bits;
} typedef ept_pdpte;

union ept_pde {
    uint64_t all;
    struct {
        uint64_t read : 1;
        uint64_t write : 1;
        uint64_t exec : 1;
        uint64_t reserved_0 : 5;
        uint64_t access : 1;
        uint64_t reserved_1 : 1;
        uint64_t exec_user : 1;
        uint64_t reserved_2 : 2;
        uint64_t physical_addr : 36;
        uint64_t reserved_3 : 4;
        uint64_t reserved_4 : 12;
    } bits;
} typedef ept_pde;

union ept_pte {
    uint64_t all;
    struct {
        uint64_t read : 1;
        uint64_t write : 1;
        uint64_t exec : 1;
        uint64_t memory_type : 3;
        uint64_t ignore_pat : 1;
        uint64_t reserved_0 : 1;
        uint64_t access : 1;
        uint64_t dirty : 1;
        uint64_t exec_user : 1;
        uint64_t reserved_2 : 1;
        uint64_t physical_addr : 36;
        uint64_t reserved_3 : 4;
        uint64_t reserved_4 : 11;
        uint64_t suppress_ve_exception : 1;
    } bits;
} typedef ept_pte;

// EPT pointer, settings for all pagetables & pagetable base pointer
union ept_pointer {
    uint64_t all;
    struct {
        uint64_t memory_type : 3;
        uint64_t page_table_walk_len : 3; // Length of pagetable walk - 1
        uint64_t enable_dirty_flag_access : 1;
        uint64_t enable_access_right_enforcement_for_supervisor_shadowstack : 1;
        uint64_t reserved_0 : 4;
        uint64_t base : 52;
    } bits;
} typedef ept_pointer;

#define EPT_PAGE_TABLE_MASK 0x0
#define EPT_RWX             0x7

// Exit qualifications for EPT violations
union ept_exit_violation {
    uint64_t all;
    struct {
        uint64_t data_read : 1;
        uint64_t data_write : 1;
        uint64_t instruction_fetch : 1;
        uint64_t and_bit_0_cause : 1;
        uint64_t and_bit_1_cause : 1;
        uint64_t and_bit_2_cause : 1;
        uint64_t and_bit_10 : 1;
        uint64_t guest_linear_addr_valid : 1;
        uint64_t guest_addr_translation_of_linear_addr : 1;
        uint64_t user_mode_linear_addr : 1;
        uint64_t rw_page : 1;
        uint64_t exec_disabled_page : 1;
        uint64_t nmi_unblocking_due_to_iret : 1;
        uint64_t shadow_stack_access : 1;
        uint64_t ept_entry_bit_60 : 1;
        uint64_t guest_paging_verification : 1;
        uint64_t access_async_to_instr_exec : 1;
        uint64_t reserved_0 : 46;
    } bits;
} typedef ept_exit_violation;

void     ept_set_memory_region(internal_guest *g, internal_memory_region *memory_region);
uint64_t ept_map_page_attributes_to_arch(uint64_t attrib);
uint64_t ept_map_arch_to_page_attributes(uint64_t attrib);
void     ept_init_mmu(internal_mmu *m);
void     ept_destroy_mmu(internal_mmu *m);
uint64_t ept_get_vpn_from_level(uint64_t virt_addr, unsigned int level);
int      ept_mmu_walk_available(hpa_t *pte, gpa_t phys_guest, unsigned int *current_level);
hpa_t*   ept_mmu_walk_next(hpa_t *pte, gpa_t phys_guest, unsigned int *current_level);
hpa_t*   ept_mmu_walk_init(internal_mmu *m, gpa_t phys_guest, unsigned int *current_level);
gpa_t    ept_mmu_gva_to_gpa(internal_guest *g, gva_t virt_guest);

int check_ept_available();