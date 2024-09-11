#include <svm/npt.h>

void svm_set_memory_region(internal_guest *g, internal_memory_region *memory_region) {
	// TODO
}

uint64_t svm_map_page_attributes_to_arch(uint64_t attrib) {
	uint64_t 	ret = 0;

	if ((attrib & PAGE_ATTRIB_WRITE) != 0) 		ret |= _PAGE_RW;
	if ((attrib & PAGE_ATTRIB_EXEC) == 0) 		ret |= _PAGE_NX;
	if ((attrib & PAGE_ATTRIB_PRESENT) != 0) 	ret |= _PAGE_PRESENT;
	if ((attrib & PAGE_ATTRIB_DIRTY) != 0) 		ret |= _PAGE_DIRTY;
	if ((attrib & PAGE_ATTRIB_ACCESSED) != 0) 	ret |= _PAGE_ACCESSED;
	if ((attrib & PAGE_ATTRIB_HUGE) != 0) 		ret |= _PAGE_SPECIAL;
	
	// For AMD SVM, a nested page always has to be a user page
	ret |= _PAGE_USER;

	return ret;
}

uint64_t svm_map_arch_to_page_attributes(uint64_t attrib) {
	uint64_t 	ret = 0;

	// On x86, a page is always readable
	ret |= PAGE_ATTRIB_READ;

	if ((attrib & _PAGE_RW) != 0) 			ret |= PAGE_ATTRIB_WRITE;
	if ((attrib & _PAGE_NX) == 0) 			ret |= PAGE_ATTRIB_EXEC;
	if ((attrib & _PAGE_PRESENT) != 0) 		ret |= PAGE_ATTRIB_PRESENT;
	if ((attrib & _PAGE_DIRTY) != 0) 		ret |= PAGE_ATTRIB_DIRTY;
	if ((attrib & _PAGE_ACCESSED) != 0)		ret |= PAGE_ATTRIB_ACCESSED;
	if ((attrib & _PAGE_USER) != 0) 		ret |= PAGE_ATTRIB_USER;
	if ((attrib & _PAGE_SPECIAL) != 0)		ret |= PAGE_ATTRIB_HUGE;

	return ret;
}

void svm_init_mmu(internal_mmu *m) {
	m->levels = 4;
	m->base = kzalloc(PAGE_SIZE, GFP_KERNEL);
	INIT_LIST_HEAD(&m->pagetables_list);
	INIT_LIST_HEAD(&m->memory_region_list);
}

void svm_destroy_mmu(internal_mmu *m) {
	if (m->base) kfree(m->base);
}

// The following functions implement 4-level nested pages (4KB pages) for SVM
uint64_t svm_get_vpn_from_level(uint64_t virt_addr, unsigned int level) {
    return (virt_addr >> ((level-1)*9 + 12)) & (uint64_t)0x1ff;
}

int svm_mmu_walk_available(hpa_t *pte, gpa_t phys_guest, unsigned int *current_level) {
	//printk(DBG "svm_mmu_walk_available\n");
	if ((*pte & PAGE_TABLE_MASK) == 0) return -EINVAL;
	else return 0;
}

hpa_t* svm_mmu_walk_next(hpa_t *pte, gpa_t phys_guest, unsigned int *current_level) {
	uint64_t	vpn;
	hpa_t*		next_base;

	*current_level  = *current_level - 1;

	vpn = svm_get_vpn_from_level(phys_guest, *current_level);
	next_base = (hpa_t*)__va(*pte & PAGE_TABLE_MASK);

	//printk(DBG "svm_mmu_walk_next\n");
	//printk(DBG "next_base: 0x%lx\n", (unsigned long)next_base);

	return (hpa_t*)&next_base[vpn];
}

hpa_t* svm_mmu_walk_init(internal_mmu *m, gpa_t phys_guest, unsigned int *current_level) {
	uint64_t	vpn = svm_get_vpn_from_level(phys_guest, *current_level);
	//printk(DBG "svm_mmu_walk_init\n");
	*current_level  = m->levels;
	return &(m->base[vpn]);
}

gpa_t svm_mmu_gva_to_gpa(internal_guest *g, gva_t virt_guest) {
	// TODO

	// First, get the cr3 register of the guest: use the first VCPU

	// Check if the VCPU is in long mode

	// Do a pagetable walk for the guest pages

	return 0;
}