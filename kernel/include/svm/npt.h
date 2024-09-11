#pragma once

#include <guest.h>
#include <memory.h>
#include <stddef.h>

void     svm_set_memory_region(internal_guest *g, internal_memory_region *memory_region);
uint64_t svm_map_page_attributes_to_arch(uint64_t attrib);
uint64_t svm_map_arch_to_page_attributes(uint64_t attrib);
void     svm_init_mmu(internal_mmu *m);
void     svm_destroy_mmu(internal_mmu *m);
uint64_t svm_get_vpn_from_level(uint64_t virt_addr, unsigned int level);
int      svm_mmu_walk_available(hpa_t *pte, gpa_t phys_guest, unsigned int *current_level);
hpa_t*   svm_mmu_walk_next(hpa_t *pte, gpa_t phys_guest, unsigned int *current_level);
hpa_t*   svm_mmu_walk_init(internal_mmu *m, gpa_t phys_guest, unsigned int *current_level);
gpa_t    svm_mmu_gva_to_gpa(internal_guest *g, gva_t virt_guest);