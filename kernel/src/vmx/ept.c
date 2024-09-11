#include <vmx/ept.h>

int check_ept_available() {
    // TODO
    return 0;
}

void ept_init_mmu(internal_mmu *m) {
	m->levels = 4;
	m->base = kzalloc(PAGE_SIZE, GFP_KERNEL);
	INIT_LIST_HEAD(&m->pagetables_list);
	INIT_LIST_HEAD(&m->memory_region_list);
}

uint64_t ept_get_config(internal_mmu *m) {
    ept_pointer ept_p;

    ept_p.all = 0;
    ept_p.bits.page_table_walk_len = 3; // Page table walk length (4) - 1
    ept_p.bits.memory_type = VMX_EPT_CACHE_MEMORY_TYPE_UC;
    ept_p.bits.base = m->base;

    return ept_p.all;
}

void ept_destroy_mmu(internal_mmu *m) {
	if (m->base) kfree(m->base);
}

uint64_t ept_get_vpn_from_level(uint64_t virt_addr, unsigned int level) {
    return (virt_addr >> ((level-1)*9 + 12)) & (uint64_t)0x1ff;
}

int ept_mmu_walk_available(hpa_t *pte, gpa_t phys_guest, unsigned int *current_level) {
    // On EPT, if RWX is not set, the page is not present.
	if ((*pte & EPT_RWX) == 0) return -EINVAL;
	else return 0;
}

hpa_t* ept_mmu_walk_next(hpa_t *pte, gpa_t phys_guest, unsigned int *current_level) {
	uint64_t	vpn;
	hpa_t*		next_base;

    ept_pml4e   l4_page;
    ept_pdpte   l3_page;
    ept_pde     l2_page;
    ept_pte     l1_page;

    uint64_t    pfn;

    switch(*current_level) {
        case 0:
            l1_page.all = *pte;
            pfn = l1_page.bits.physical_addr;
            break;
        case 1:
            l2_page.all = *pte;
            pfn = l2_page.bits.physical_addr;
            break;
        case 2:
            l3_page.all = *pte;
            pfn = l3_page.bits.physical_addr;
            break;
        case 3:
            l4_page.all = *pte;
            pfn = l4_page.bits.physical_addr;
            break;
    }

	*current_level  = *current_level - 1;

	vpn = ept_get_vpn_from_level(phys_guest, *current_level);
	next_base = (hpa_t*)__va(pfn);

	return (hpa_t*)&next_base[vpn];
}

hpa_t* ept_mmu_walk_init(internal_mmu *m, gpa_t phys_guest, unsigned int *current_level) {
	uint64_t	vpn = ept_get_vpn_from_level(phys_guest, *current_level);
	*current_level  = m->levels;
	return &(m->base[vpn]);
}

gpa_t ept_mmu_gva_to_gpa(internal_guest *g, gva_t virt_guest) {
	// TODO
	return 0;
}