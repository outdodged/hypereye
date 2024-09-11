/*
 * 32-Bit code for building the pagetables. This code will be called by the start.S file
 * before execution is passed to the 64-bit code.
 */

#include "os.h"

#include <stdlib.h>

#define PAGE_SIZE       0x1000

#define MAX_PAGES       0x100

void* pages_slab_heap[MAX_PAGES];
uint8_t pages_slab_heap_free[MAX_PAGES];

// Pagetable walker functions
uint64_t get_vpn_from_level(uint64_t virt, unsigned int level) {
    return (virt >> ((level-1)*9 + 12)) & (uint64_t)0x1ff;
}

uint64_t* walk_next(uint64_t *pte, uint64_t phys_guest, unsigned int *current_level) {
	uint64_t	vpn;
	uint64_t    *next_base;

	*current_level  = *current_level - 1;

	vpn = get_vpn_from_level(phys_guest, *current_level);
	next_base = (uint64_t*)(*pte & PAGE_TABLE_MASK);

	return (uint64_t*)&next_base[vpn];
}

uint64_t* walk_init(uint64_t *base, uint64_t virt, unsigned int *current_level) {
	uint64_t	vpn = get_vpn_from_level(virt, *current_level);
	*current_level  = 4;
	return &base[vpn];
}

#define for_each_mmu_level(x,base,phys_guest,i) for(x = walk_init(base, phys_guest, &i); i > 0; x = walk_next(x, phys_guest, &i))

// Pagetable allocation
void* allocate_pagetable(void) {
    for (unsigned int i = 0; i < MAX_PAGES; i++) {
        if (pages_slab_heap_free[i] == 0) {
            pages_slab_heap_free[i] = 1;
            return &pages_slab_heap[i];
        }
    }
    return NULL;
}

// Add mapping from a virtual to a phyiscal address
 void map_to_32(uint64_t *base, uint64_t virt, uint64_t phys) {
    unsigned int    level;
    uint64_t        *current_pte;
	uint64_t		*next_base;

    for_each_mmu_level(current_pte, base, virt, level) {
        if (level == 1) {
            *current_pte = phys | PAGE_ATTRIB_WRITE | PAGE_ATTRIB_PRESENT;
			return;
        }

        if ((*current_pte & PAGE_TABLE_MASK) == 0) {
            next_base = allocate_pagetable();

            *current_pte = (uint64_t)next_base | PAGE_ATTRIB_WRITE | PAGE_ATTRIB_PRESENT;
            if (next_base == NULL) {
				return;
			}
        }
    }

    return;
}

// Create a 1-to-1 mapping for the first 1MB of memory.
void* create_mapping_32(void) {
    // Allocate the root pagetable (cr3)
    pages_slab_heap_free[0] = 1;

    for (uint64_t addr = 0; addr < 0x10000; addr += PAGE_SIZE) {
        map_to_32((uint64_t*)(&pages_slab_heap[0]), addr, addr);
    }

    return &pages_slab_heap[0];
}