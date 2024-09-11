#include <memory.h>
#include <guest.h>
#include <HYPEREYE_defs.h>
#include <stddef.h>

#include <linux/slab.h>
#include <asm/pgtable.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/mmap_lock.h>
#include <linux/highmem.h>
#include <linux/io.h>

unsigned int mmu_get_index_of_page_in_memory_region(gpa_t phys_guest, internal_memory_region *region) {
	return (unsigned int)(phys_guest - region->guest_addr) / PAGE_SIZE;
}

int map_user_memory(internal_mmu* m, hpa_t *base, gpa_t phys_guest, hva_t virt_user, internal_memory_region *region) {
	struct 			vm_area_struct *vma;
	int 			err;
	unsigned int 	idx;

	printk(DBG "map_user_memory\n");

	err = 0;

	mmap_read_lock(current->mm);

	vma = find_vma(current->mm, virt_user);
	if (!vma) {
		printk(DBG "vma not found!\n");
		err = -EFAULT;
		goto ret;
	}

	idx = mmu_get_index_of_page_in_memory_region(phys_guest, region);

	if (idx > region->size / PAGE_SIZE) {
		printk(DBG "idx out of range: 0x%lx\n", (unsigned long)idx);
		err = -EFAULT;
		goto ret;
	}

	printk(DBG "pinning user page: 0x%lx\n", (unsigned long)virt_user);
	err = pin_user_pages(virt_user, 1, FOLL_LONGTERM | FOLL_WRITE | FOLL_FORCE, region->pages + idx, NULL);
	// pin_user_pages returns the number of pages which were pinned
	if (err != 1) goto ret;

	printk(DBG "pa of user page: 0x%lx\n", (unsigned long)(page_to_pfn(region->pages[idx]) << 12));
	err = map_nested_pages_to(m, base, phys_guest, page_to_pfn(region->pages[idx]) << 12);

ret:
	mmap_read_unlock(current->mm);

	return err;
}

void unmap_user_memory(internal_memory_region *region) {
	int				i;

	mmap_read_lock(current->mm);

	for (i = 0; i < (region->size / PAGE_SIZE); i++) {
		if (region->pages[i] != NULL)
			unpin_user_pages(&((region->pages)[i]), 1);

	}
	mmap_read_unlock(current->mm);
}

void mmu_prepare_page_for_cow(internal_mmu *m, gpa_t phys_guest, internal_memory_region *region) {
	// Mark the old nested pagetable entry as read-only
	set_pagetable_attributes(m, phys_guest, PAGE_ATTRIB_READ | PAGE_ATTRIB_EXEC | PAGE_ATTRIB_PRESENT);
}

void mmu_do_page_cow(internal_mmu *m, gpa_t phys_guest, internal_memory_region *region) {
	unsigned int 	idx;
	void*			page_map;
	unsigned int    level;
    hpa_t	        *current_pte;

	printk(DBG "mmu_do_page_cow\n");

	// Copy the contents of the old read-only page to the new writable page
	idx = mmu_get_index_of_page_in_memory_region(phys_guest, region);

	region->modified_pages[idx] = kmalloc(PAGE_SIZE, GFP_KERNEL);

	page_map = kmap(region->pages[idx]);

	memcpy(region->modified_pages[idx], page_map, PAGE_SIZE);

	kunmap(region->pages[idx]);

	// Now let the pagetable entry point to the new writable page
	for_each_mmu_level(current_pte, m, phys_guest, level) {
        if (level == 1) {
            *current_pte = __pa(region->modified_pages[idx]) | HYPEREYE_ops.map_page_attributes_to_arch(PAGE_ATTRIB_READ | 
                                                                                  				   PAGE_ATTRIB_WRITE | 
                                                                                  				   PAGE_ATTRIB_EXEC | 
                                                                                  				   PAGE_ATTRIB_PRESENT);
			break;
        }
    }
}

void mmu_rollback_cow_pages(internal_mmu *m, internal_memory_region *region) {
	unsigned int 	i;
	gpa_t 			phys_guest;

	for (i = 0; i < (region->size / PAGE_SIZE); i++) {
		phys_guest = region->guest_addr + i * PAGE_SIZE;

		if (region->modified_pages[i] != NULL) {
			map_nested_pages_to(m, m->base, phys_guest, page_to_pfn(region->pages[i]) << 12);
			kfree(region->modified_pages[i]);
			region->modified_pages[i] = NULL;
		}

	}
}

int handle_pagefault(internal_guest *g, internal_vcpu *vcpu, hpa_t *base, gpa_t phys_guest, uint64_t reason) {
	internal_memory_region 	*region;

	printk(DBG "handle_pagefault, reason: 0x%llx\n", reason);

	// First, map the guest address which is responsible for the fault to a memory region.
	region = mmu_map_guest_addr_to_memory_region(g->mmu, phys_guest);

	printk(DBG "Found memory region: 0x%lx\n", (unsigned long)region);
	
	if (region == NULL) goto err;

	// It the region is not a MMIO region, simply do lazy faulting and "swap in" the page.
	if (!region->is_mmio) {
		printk(DBG "no MMIO\n");
		
		if (reason & PAGEFAULT_NON_PRESENT) {
			if (map_user_memory(g->mmu, base, phys_guest & PAGE_TABLE_MASK, (region->userspace_addr + (phys_guest - region->guest_addr)) & PAGE_TABLE_MASK, region)) {
				printk(DBG "map_user_memory error\n");
			}
		}

		if (region->is_cow) {
			// Directly check afterwards, if we also pagefaulted on a CoW page
			if (reason & PAGEFAULT_WRITE) {
				mmu_prepare_page_for_cow(g->mmu, phys_guest, region);
				mmu_do_page_cow(g->mmu, phys_guest, region);
			}
		}
	}

	// If there is a fault upon accessing an MMIO region, do the arch-dependent emulation.
	if (region->is_mmio) {
		printk(DBG "MMIO\n");

		if (reason & PAGEFAULT_NON_PRESENT) {
			map_user_memory(g->mmu, base, phys_guest, region->userspace_addr + (phys_guest - region->guest_addr), region);
			HYPEREYE_ops.handle_mmio(vcpu, phys_guest, (reason & PAGEFAULT_WRITE ? 1 : 0));
			HYPEREYE_ops.singlestep(g, vcpu);
			set_pagetable_attributes(g->mmu, phys_guest, PAGE_ATTRIB_READ | PAGE_ATTRIB_EXEC);
		}

		return 0;
	}

err:
	return -EFAULT;
}

void mmu_add_memory_region(internal_mmu *m, internal_memory_region *region) {
    list_add_tail(&region->list_node, &m->memory_region_list);

	printk(DBG "Adding memory region: 0x%lx\n", (unsigned long)region);
}

void mmu_destroy_all_memory_regions(internal_mmu *m) {
    internal_memory_region *r, *tmp_r;

    list_for_each_entry_safe(r, tmp_r, &m->memory_region_list, list_node) {
        if (r != NULL) {
			printk(DBG "Removing memory region: 0x%lx\n", (unsigned long)r);

			unmap_user_memory(r);
			mmu_rollback_cow_pages(m, r);
			if (r->pages != NULL) kfree(r->pages);
			if (r->modified_pages != NULL) kfree(r->modified_pages);
            list_del(&r->list_node);
            kfree(r);
        }
    }
}

internal_memory_region* mmu_map_guest_addr_to_memory_region(internal_mmu *m, gpa_t phys_guest) {
	internal_memory_region *r;

	list_for_each_entry(r, &m->memory_region_list, list_node) {
		//printk(DBG "\tLooking @ memory region: 0x%lx, @ guest addr: 0x%lx\n", (unsigned long)r, (unsigned long)r->guest_addr);
		if (r->guest_addr <= phys_guest && (r->guest_addr + r->size) > phys_guest) {
			return r;
		}
	}

	return NULL;
}

void mmu_add_pagetable(internal_mmu *m, void* pagetable_ptr) {
    pagetable 	*p;
    p = kmalloc(sizeof(pagetable), GFP_KERNEL);
	p->pagetable = pagetable_ptr;
    list_add_tail(&p->list_node, &m->pagetables_list);

	printk(DBG "Adding pagetable: 0x%lx\n", (unsigned long)pagetable_ptr);
}

void mmu_destroy_all_pagetables(internal_mmu *m) {
    pagetable 	*p, *tmp_p;

    list_for_each_entry_safe(p, tmp_p, &m->pagetables_list, list_node) {
        if (p != NULL) {
			printk(DBG "Removing pagetable: 0x%lx\n", (unsigned long)p->pagetable);

			if (p->pagetable != NULL) kfree(p->pagetable);
            list_del(&p->list_node);
            kfree(p);
        }
    }
}

int map_nested_pages_to(internal_mmu *m, hpa_t *base, gpa_t phys_guest, hpa_t phys_host) {
    unsigned int    level;
    hpa_t          	*current_pte;
	hpa_t			*next_base;

	printk(DBG "map_nested_pages_to\n");

    for_each_mmu_level(current_pte, m, phys_guest, level) {
		printk(DBG "current_pte va: 0x%lx\n", (unsigned long)*current_pte);
		printk(DBG "current_pte pa: 0x%lx\n", (unsigned long)__pa(*current_pte));
		printk(DBG "level: 0x%lx\n", (unsigned long)level);

        if (level == 1) {
			printk(DBG "level 1 *current_pte: 0x%lx\n", (unsigned long)*current_pte);

             *current_pte = phys_host | HYPEREYE_ops.map_page_attributes_to_arch(PAGE_ATTRIB_READ | 
																			PAGE_ATTRIB_WRITE | 
																			PAGE_ATTRIB_EXEC | 
																			PAGE_ATTRIB_PRESENT);
			return 0;
        }

        if (HYPEREYE_ops.mmu_walk_available(current_pte, phys_guest, &level)) {
            next_base = kzalloc(PAGE_SIZE, GFP_KERNEL);
			mmu_add_pagetable(m, next_base);
			printk(DBG "next_base: 0x%lx\n", (unsigned long)next_base);
            *current_pte = __pa(next_base) | HYPEREYE_ops.map_page_attributes_to_arch(PAGE_ATTRIB_READ | 
                                                                                  PAGE_ATTRIB_WRITE | 
                                                                                  PAGE_ATTRIB_EXEC | 
                                                                                  PAGE_ATTRIB_PRESENT);
			printk(DBG "*current_pte: 0x%lx\n", (unsigned long)*current_pte);
            if (next_base == NULL) {
				return -EFAULT;
			}
        }
    }

    return -EFAULT;
}

int set_pagetable_attributes(internal_mmu *m, gpa_t phys_guest, uint64_t attributes) {
	unsigned int    level;
    hpa_t	        *current_pte;

    for_each_mmu_level(current_pte, m, phys_guest, level) {
        if (level == 1) {
            *current_pte = (*current_pte & PAGE_TABLE_MASK) | HYPEREYE_ops.map_page_attributes_to_arch(attributes);
			return 0;
        }
    }

    return -EFAULT;
}

uint64_t get_pagetable_attributes(internal_mmu *m, gpa_t phys_guest) {
	unsigned int    level;
    hpa_t          	*current_pte;

    for_each_mmu_level(current_pte, m, phys_guest, level) {
        if (level == 1) {
            return HYPEREYE_ops.map_arch_to_page_attributes(*current_pte);
        }
    }

    return -1;
}

int  write_memory(internal_mmu *m, gpa_t phys_guest, void *src, size_t sz) {
	unsigned int    		level;
    hpa_t          			*current_pte;
	void*					page_ptr;
	internal_memory_region* region;

	if (sz > PAGE_SIZE) return -EINVAL;

	region = mmu_map_guest_addr_to_memory_region(m, phys_guest);

	for_each_mmu_level(current_pte, m, phys_guest, level) {
        if (level == 1) {
			//printk(DBG "memremap at mem: 0x%lx\n", (*current_pte & PAGE_TABLE_MASK));
			page_ptr = memremap((resource_size_t)(*current_pte & PAGE_TABLE_MASK), PAGE_SIZE, MEMREMAP_WB);
			if (page_ptr != NULL) {
				memcpy((void*)(page_ptr + (phys_guest & PAGE_OFFSET_MASK)), src, sz);
				memunmap(page_ptr);
				return 0;
			} else {
				printk(DBG "memremap error\n");
				return -EFAULT;
			}
        }

		// Map the user memory if it is not available
		if (HYPEREYE_ops.mmu_walk_available(current_pte, phys_guest, &level)) {
			goto map_mem;
		}
    }

map_mem:
	// Map the user memory if it is not available
	if (map_user_memory(m, m->base, phys_guest & PAGE_TABLE_MASK, (region->userspace_addr + (phys_guest - region->guest_addr)) & PAGE_TABLE_MASK, region)) {
		printk(DBG "map_user_memory error\n");
		return -EFAULT;
	}

	for_each_mmu_level(current_pte, m, phys_guest, level) {
        if (level == 1) {
			//printk(DBG "memremap at mem: 0x%lx\n", (*current_pte & PAGE_TABLE_MASK));
			page_ptr = memremap((resource_size_t)(*current_pte & PAGE_TABLE_MASK), PAGE_SIZE, MEMREMAP_WB);
			if (page_ptr != NULL) {
				memcpy((void*)(page_ptr + (phys_guest & PAGE_OFFSET_MASK)), src, sz);
				memunmap(page_ptr);
				return 0;
			} else {
				printk(DBG "memremap error\n");
				return -EFAULT;
			}
        }
    }

	return -EFAULT;
}

int  read_memory(internal_mmu *m, gpa_t phys_guest, void *dst, size_t sz) {
	unsigned int    		level;
    hpa_t          			*current_pte;
	void*					page_ptr;
	internal_memory_region* region;

	if (sz > PAGE_SIZE) return -EINVAL;

	region = mmu_map_guest_addr_to_memory_region(m, phys_guest);

	for_each_mmu_level(current_pte, m, phys_guest, level) {
        if (level == 1) {
			//printk(DBG "memremap at mem: 0x%lx\n", (*current_pte & PAGE_TABLE_MASK));
			page_ptr = memremap((resource_size_t)(*current_pte & PAGE_TABLE_MASK), PAGE_SIZE, MEMREMAP_WB);
			if (page_ptr != NULL) {
				memcpy(dst, (void*)(page_ptr + (phys_guest & PAGE_OFFSET_MASK)), sz);
				memunmap(page_ptr);
				return 0;
			} else {
				printk(DBG "memremap error\n");
				return -EFAULT;
			}
        }

		// Map the user memory if it is not available
		if (HYPEREYE_ops.mmu_walk_available(current_pte, phys_guest, &level)) {
			goto map_mem;
		}
    }

map_mem:
	// Map the user memory if it is not available
	if (map_user_memory(m, m->base, phys_guest & PAGE_TABLE_MASK, (region->userspace_addr + (phys_guest - region->guest_addr)) & PAGE_TABLE_MASK, region)) {
		printk(DBG "map_user_memory error\n");
		return -EFAULT;
	}

	for_each_mmu_level(current_pte, m, phys_guest, level) {
        if (level == 1) {
			//printk(DBG "memremap at mem: 0x%lx\n", (*current_pte & PAGE_TABLE_MASK));
			page_ptr = memremap((resource_size_t)(*current_pte & PAGE_TABLE_MASK), PAGE_SIZE, MEMREMAP_WB);
			if (page_ptr != NULL) {
				memcpy(dst, (void*)(page_ptr + (phys_guest & PAGE_OFFSET_MASK)), sz);
				memunmap(page_ptr);
				return 0;
			} else {
				printk(DBG "memremap error\n");
				return -EFAULT;
			}
        }
    }

	return -EFAULT;
}