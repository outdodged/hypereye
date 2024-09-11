#include <svm/svm.h>
#include <svm/svm_ops.h>
#include <guest.h>
#include <memory.h>
#include <stddef.h>
#include <HYPEREYE.h>
#include <x86/x86.h>

#include <linux/slab.h>

void* svm_create_arch_internal_guest(internal_guest *g) {
	svm_internal_guest	*svm_g;
	unsigned int 		i;

	svm_g = (svm_internal_guest*) kzalloc(sizeof(internal_guest), GFP_KERNEL);
	TEST_PTR(svm_g, svm_internal_guest*,,NULL)
	
	// Get the root for the nested pagetables from the MMU.
	svm_g->nested_pagetables = g->mmu->base;

	// SVM offers the possibility to intercept MSR instructions via a 
	// SVM MSR permissions map (MSR). Each MSR is covered by two bits,
	// the lsb controls read access and the msb controls write acccess.
	// The MSR bitmap consists of 4 bit vectors of 2kB each.
	// MSR bitmap offset        MSR range
	// 0x0      - 0x7FFF:        0x0        - 0x1FFF
	// 0x800    - 0xFFFF:        0xC0000000 - 0xC0001FFF
	// 0x1000   - 0x17FFF:       0xC0010000 - 0xC0011FFF
	// 0x1800   - 0x1FFFF:       Reserved
	svm_g->msr_permission_map = (uint8_t*) kzalloc(MSRPM_SIZE, GFP_KERNEL);
	TEST_PTR(svm_g->msr_permission_map, uint8_t*, kfree(svm_g), NULL)

	for(i = 0; i < MSRPM_SIZE; i++) svm_g->msr_permission_map[i] = 0;

	// We only allow direct access to a few selected MSRs.
	svm_set_msrpm_permission(svm_g->msr_permission_map, MSR_STAR, 1, 1);
	svm_set_msrpm_permission(svm_g->msr_permission_map, MSR_LSTAR, 1, 1);
	svm_set_msrpm_permission(svm_g->msr_permission_map, MSR_CSTAR, 1, 1);
	svm_set_msrpm_permission(svm_g->msr_permission_map, MSR_IA32_SYSENTER_CS, 1, 1);
	svm_set_msrpm_permission(svm_g->msr_permission_map, MSR_IA32_SYSENTER_ESP, 1, 1);
	svm_set_msrpm_permission(svm_g->msr_permission_map, MSR_IA32_SYSENTER_EIP, 1, 1);
	svm_set_msrpm_permission(svm_g->msr_permission_map, MSR_GS_BASE, 1, 1);
	svm_set_msrpm_permission(svm_g->msr_permission_map, MSR_FS_BASE, 1, 1);
	svm_set_msrpm_permission(svm_g->msr_permission_map, MSR_KERNEL_GS_BASE, 1, 1);
	svm_set_msrpm_permission(svm_g->msr_permission_map, MSR_SYSCALL_MASK, 1, 1);
	/*svm_set_msrpm_permission(svm_g->msr_permission_map, MSR_IA32_SPEC_CTRL, 1, 1);
	svm_set_msrpm_permission(svm_g->msr_permission_map, MSR_IA32_PRED_CMD, 1, 1);
	svm_set_msrpm_permission(svm_g->msr_permission_map, MSR_IA32_LASTBRANCHFROMIP, 1, 1);
	svm_set_msrpm_permission(svm_g->msr_permission_map, MSR_IA32_LASTBRANCHTOIP, 1, 1);
	svm_set_msrpm_permission(svm_g->msr_permission_map, MSR_IA32_LASTINTFROMIP, 1, 1);
	svm_set_msrpm_permission(svm_g->msr_permission_map, MSR_IA32_LASTINTTOIP, 1, 1);*/

	return (void*)svm_g;
}

void* svm_simple_copy_arch_internal_guest(internal_guest *g, internal_guest *copy_g) {
	svm_internal_guest	*svm_g;
	svm_internal_guest	*copy_svm_g;

	TEST_PTR(g, internal_guest*,, NULL)
	svm_g = to_svm_guest(g);
	copy_svm_g = (svm_internal_guest*) kzalloc(sizeof(internal_guest), GFP_KERNEL);

	copy_svm_g->nested_pagetables = copy_g->mmu->base;

	copy_svm_g->msr_permission_map = (uint8_t*) kzalloc(MSRPM_SIZE, GFP_KERNEL);
	memcpy(copy_svm_g->msr_permission_map, svm_g->msr_permission_map, MSRPM_SIZE);

	return (void*)copy_svm_g;
}

void svm_destroy_arch_internal_guest(internal_guest *g) {
	svm_internal_guest		*svm_g;

	TEST_PTR(g, internal_guest*,,)
	svm_g = to_svm_guest(g);

	if (svm_g != NULL) {
		// If we are here, we can assume that all locks are set.
		if (svm_g->msr_permission_map != NULL) kfree(svm_g->msr_permission_map);
		if (svm_g->io_permission_map != NULL)  kfree(svm_g->io_permission_map);

		kfree(svm_g);
	}
}

void* svm_create_arch_internal_vcpu(internal_guest *g, internal_vcpu* vcpu) {
	svm_internal_guest	*svm_g;
	svm_internal_vcpu	*svm_vcpu;

	TEST_PTR(g, internal_guest*,, NULL)
	svm_g = to_svm_guest(g);
	TEST_PTR(svm_g, svm_internal_guest*,, NULL)

	// TODO: Test if creating a VCPU exceedes the phyiscal cores on the system
	
	svm_vcpu = kzalloc(sizeof(internal_vcpu), GFP_KERNEL);
	
	svm_vcpu->vcpu_vmcb = kzalloc(PAGE_SIZE, GFP_KERNEL);
	svm_vcpu->host_vmcb = kzalloc(PAGE_SIZE, GFP_KERNEL);
	svm_vcpu->vcpu_regs = kzalloc(sizeof(svm_gp_regs), GFP_KERNEL);
	
	TEST_PTR(svm_vcpu->vcpu_vmcb, internal_vmcb*, kfree(svm_vcpu), NULL);
	TEST_PTR(svm_vcpu->host_vmcb, internal_vmcb*, kfree(svm_vcpu); kfree(svm_vcpu->vcpu_vmcb), NULL);
	TEST_PTR(svm_vcpu->vcpu_regs, svm_gp_regs*, kfree(svm_vcpu); kfree(svm_vcpu->vcpu_vmcb); kfree(svm_vcpu->host_vmcb), NULL);

	svm_reset_vcpu(svm_vcpu, g);

	return (void*)svm_vcpu;
}

void* svm_simple_copy_arch_internal_vcpu(internal_guest *copy_g, internal_vcpu *vcpu, internal_vcpu* copy_vcpu) {
	svm_internal_guest	*copy_svm_g;
	svm_internal_vcpu	*copy_svm_vcpu;
	svm_internal_vcpu	*svm_vcpu;

	TEST_PTR(copy_g, internal_guest*,, NULL)
	copy_svm_g = to_svm_guest(copy_g);
	svm_vcpu = to_svm_vcpu(vcpu);
	TEST_PTR(copy_svm_g, svm_internal_guest*,, NULL)
	TEST_PTR(svm_vcpu, svm_internal_vcpu*,, NULL)

	copy_svm_vcpu = (svm_internal_vcpu*)svm_create_arch_internal_vcpu(copy_g, copy_vcpu);
	
	memcpy(copy_svm_vcpu->vcpu_vmcb, svm_vcpu->vcpu_vmcb, PAGE_SIZE);
	memcpy(copy_svm_vcpu->vcpu_regs, svm_vcpu->vcpu_regs, PAGE_SIZE);

	return (void*)copy_svm_vcpu;
}

int svm_destroy_arch_internal_vcpu(internal_vcpu *vcpu) {
	svm_internal_vcpu	*svm_vcpu;
	
	TEST_PTR(vcpu, internal_vcpu*,, ERROR);

	svm_vcpu = to_svm_vcpu(vcpu);

	if (svm_vcpu != NULL) {
		if (svm_vcpu->vcpu_vmcb != NULL) kfree(svm_vcpu->vcpu_vmcb);
		if (svm_vcpu->host_vmcb != NULL) kfree(svm_vcpu->host_vmcb);
		if (svm_vcpu->vcpu_regs != NULL) kfree(svm_vcpu->vcpu_regs);
		return 0;
	}
	return -EFAULT;
}

void svm_set_vcpu_registers(internal_vcpu *vcpu, user_arg_registers *regs) {
	svm_internal_vcpu	*svm_vcpu;

	printk(DBG "Setting registers of VCPU: 0x%lx\n", (unsigned long)vcpu);
	
	TEST_PTR(vcpu, internal_vcpu*,,);
	TEST_PTR(regs, user_arg_registers*,,);

	svm_vcpu = to_svm_vcpu(vcpu);
	TEST_PTR(svm_vcpu, svm_internal_vcpu*,,);

	TEST_PTR(svm_vcpu->vcpu_vmcb, internal_vmcb*,,);
	TEST_PTR(svm_vcpu->vcpu_regs, svm_gp_regs*,,);
	
	svm_vcpu->vcpu_vmcb->rax = regs->rax;
	svm_vcpu->vcpu_vmcb->rsp = regs->rsp;
	svm_vcpu->vcpu_vmcb->rip = regs->rip;
	
	svm_vcpu->vcpu_vmcb->cr0 = regs->cr0;
	svm_vcpu->vcpu_vmcb->cr2 = regs->cr2;
	svm_vcpu->vcpu_vmcb->cr3 = regs->cr3;
	svm_vcpu->vcpu_vmcb->cr4 = regs->cr4;
	svm_vcpu->vcpu_vmcb->rflags = regs->rflags;
	
	svm_vcpu->vcpu_vmcb->efer   = regs->efer;
	svm_vcpu->vcpu_vmcb->star   = regs->star;
	svm_vcpu->vcpu_vmcb->lstar  = regs->lstar;
	svm_vcpu->vcpu_vmcb->cstar  = regs->cstar;
	svm_vcpu->vcpu_vmcb->sfmask = regs->sfmask;
	svm_vcpu->vcpu_vmcb->kernel_gs_base = regs->kernel_gs_base;
	svm_vcpu->vcpu_vmcb->sysenter_cs    = regs->sysenter_cs;
	svm_vcpu->vcpu_vmcb->sysenter_esp   = regs->sysenter_esp;
	svm_vcpu->vcpu_vmcb->sysenter_eip   = regs->sysenter_eip;
	
	svm_vcpu->vcpu_regs->rbx = regs->rbx;
	svm_vcpu->vcpu_regs->rcx = regs->rcx;
	svm_vcpu->vcpu_regs->rdx = regs->rdx;
	svm_vcpu->vcpu_regs->rdi = regs->rdi;
	svm_vcpu->vcpu_regs->rsi = regs->rsi;
	svm_vcpu->vcpu_regs->r8  = regs->r8;
	svm_vcpu->vcpu_regs->r9  = regs->r9;
	svm_vcpu->vcpu_regs->r10 = regs->r10;
	svm_vcpu->vcpu_regs->r11 = regs->r11;
	svm_vcpu->vcpu_regs->r12 = regs->r12;
	svm_vcpu->vcpu_regs->r13 = regs->r13;
	svm_vcpu->vcpu_regs->r14 = regs->r14;
	svm_vcpu->vcpu_regs->r15 = regs->r15;
	svm_vcpu->vcpu_regs->rbp = regs->rbp;
	
	memcpy(&svm_vcpu->vcpu_vmcb->es, &regs->es, sizeof(segment));
	memcpy(&svm_vcpu->vcpu_vmcb->cs, &regs->cs, sizeof(segment));
	memcpy(&svm_vcpu->vcpu_vmcb->ss, &regs->ss, sizeof(segment));
	memcpy(&svm_vcpu->vcpu_vmcb->ds, &regs->ds, sizeof(segment));
	memcpy(&svm_vcpu->vcpu_vmcb->fs, &regs->fs, sizeof(segment));
	memcpy(&svm_vcpu->vcpu_vmcb->gs, &regs->gs, sizeof(segment));
	memcpy(&svm_vcpu->vcpu_vmcb->gdtr, &regs->gdtr, sizeof(segment));
	memcpy(&svm_vcpu->vcpu_vmcb->ldtr, &regs->ldtr, sizeof(segment));
	memcpy(&svm_vcpu->vcpu_vmcb->idtr, &regs->idtr, sizeof(segment));
	memcpy(&svm_vcpu->vcpu_vmcb->tr, &regs->tr, sizeof(segment));

	// Since registers might have been changed, set the clean bits accordingly.
	svm_vcpu->vcpu_vmcb->vmcb_clean &= ~VMCB_DIRTY_CRX;
	svm_vcpu->vcpu_vmcb->vmcb_clean &= ~VMCB_DIRTY_SEG;
	svm_vcpu->vcpu_vmcb->vmcb_clean &= ~VMCB_DIRTY_CR2;
}

void svm_get_vcpu_registers(internal_vcpu *vcpu, user_arg_registers  *regs) {
	svm_internal_vcpu	*svm_vcpu;
	
	printk(DBG "Getting registers of VCPU: 0x%lx\n", (unsigned long)vcpu);

	TEST_PTR(vcpu, internal_vcpu*,,);
	TEST_PTR(regs, user_arg_registers*,,);

	svm_vcpu = to_svm_vcpu(vcpu);
	TEST_PTR(svm_vcpu, svm_internal_vcpu*,,);

	TEST_PTR(svm_vcpu->vcpu_vmcb, internal_vmcb*,,);
	TEST_PTR(svm_vcpu->vcpu_regs, svm_gp_regs*,,);
	
	regs->rax = svm_vcpu->vcpu_vmcb->rax;
	regs->rsp = svm_vcpu->vcpu_vmcb->rsp;
	regs->rip = svm_vcpu->vcpu_vmcb->rip;
	
	regs->cr0 = svm_vcpu->vcpu_vmcb->cr0;
	regs->cr2 = svm_vcpu->vcpu_vmcb->cr2;
	regs->cr3 = svm_vcpu->vcpu_vmcb->cr3;
	regs->cr4 = svm_vcpu->vcpu_vmcb->cr4;
	regs->rflags = svm_vcpu->vcpu_vmcb->rflags;
	
	regs->efer   = svm_vcpu->vcpu_vmcb->efer;
	regs->star   = svm_vcpu->vcpu_vmcb->star;
	regs->lstar  = svm_vcpu->vcpu_vmcb->lstar;
	regs->cstar  = svm_vcpu->vcpu_vmcb->cstar;
	regs->sfmask = svm_vcpu->vcpu_vmcb->sfmask;
	regs->kernel_gs_base = svm_vcpu->vcpu_vmcb->kernel_gs_base;
	regs->sysenter_cs    = svm_vcpu->vcpu_vmcb->sysenter_cs;
	regs->sysenter_esp   = svm_vcpu->vcpu_vmcb->sysenter_esp;
	regs->sysenter_eip   = svm_vcpu->vcpu_vmcb->sysenter_eip;
	
	regs->rbx = svm_vcpu->vcpu_regs->rbx;
	regs->rcx = svm_vcpu->vcpu_regs->rcx;
	regs->rdx = svm_vcpu->vcpu_regs->rdx;
	regs->rdi = svm_vcpu->vcpu_regs->rdi;
	regs->rsi = svm_vcpu->vcpu_regs->rsi;
	regs->r8  = svm_vcpu->vcpu_regs->r8;
	regs->r9  = svm_vcpu->vcpu_regs->r9;
	regs->r10 = svm_vcpu->vcpu_regs->r10;
	regs->r11 = svm_vcpu->vcpu_regs->r11;
	regs->r12 = svm_vcpu->vcpu_regs->r12;
	regs->r13 = svm_vcpu->vcpu_regs->r13;
	regs->r14 = svm_vcpu->vcpu_regs->r14;
	regs->r15 = svm_vcpu->vcpu_regs->r15;
	regs->rbp = svm_vcpu->vcpu_regs->rbp;
	
	memcpy(&regs->es, &svm_vcpu->vcpu_vmcb->es, sizeof(segment));
	memcpy(&regs->cs, &svm_vcpu->vcpu_vmcb->cs, sizeof(segment));
	memcpy(&regs->ss, &svm_vcpu->vcpu_vmcb->ss, sizeof(segment));
	memcpy(&regs->ds, &svm_vcpu->vcpu_vmcb->ds, sizeof(segment));
	memcpy(&regs->fs, &svm_vcpu->vcpu_vmcb->fs, sizeof(segment));
	memcpy(&regs->gs, &svm_vcpu->vcpu_vmcb->gs, sizeof(segment));
	memcpy(&regs->gdtr, &svm_vcpu->vcpu_vmcb->gdtr, sizeof(segment));
	memcpy(&regs->ldtr, &svm_vcpu->vcpu_vmcb->ldtr, sizeof(segment));
	memcpy(&regs->idtr, &svm_vcpu->vcpu_vmcb->idtr, sizeof(segment));
	memcpy(&regs->tr, &svm_vcpu->vcpu_vmcb->tr, sizeof(segment));
}

int svm_add_breakpoint_p(internal_guest *g, gpa_t guest_addr) {
	uint8_t 				old_byte;
	uint8_t 				new_byte;
	internal_breakpoint 	*bp;
	int						ret;

	printk(DBG "svm_add_breakpoint_p\n");

	ret = read_memory(g->mmu, guest_addr, &old_byte, 1);
	printk(DBG "read at: 0x%lx, val: 0x%lx\n", guest_addr, old_byte);
	if (ret) goto err;

	new_byte = 0xcc;
	ret = write_memory(g->mmu, guest_addr, &new_byte, 1);
	if (ret) goto err;

	bp = kmalloc(sizeof(internal_breakpoint), GFP_KERNEL);
	if (bp == NULL) {
		ret = -EFAULT;
		goto err;
	}

	bp->old_mem = old_byte;
	bp->guest_addr_p = guest_addr;
	bp->num = g->breakpoints_cnt;

	insert_breakpoint(g, bp);

	g->breakpoints_cnt++;

err:
	return ret;
}

int svm_add_breakpoint_v(internal_guest *g, gva_t guest_addr) {
	uint8_t 				old_byte;
	uint8_t 				new_byte;
	internal_breakpoint 	*bp;
	gpa_t					phys_guest;
	int						ret;

	printk(DBG "svm_add_breakpoint_v\n");

	ret = 0;
	phys_guest = svm_mmu_gva_to_gpa(g, guest_addr);

	ret = read_memory(g->mmu, phys_guest, &old_byte, 1);
	if (ret) goto err;

	new_byte = 0xcc;
	ret = write_memory(g->mmu, phys_guest, &new_byte, 1);
	if (ret) goto err;

	bp = kmalloc(sizeof(internal_breakpoint), GFP_KERNEL);
	if (bp == NULL) {
		ret = -EFAULT;
		goto err;
	}

	bp->old_mem = old_byte;
	bp->guest_addr_p = phys_guest;
	bp->guest_addr_v = guest_addr;
	bp->num = g->breakpoints_cnt;

	insert_breakpoint(g, bp);

	g->breakpoints_cnt++;

err:
	return ret;
}

int svm_remove_breakpoint(internal_guest *g, internal_vcpu *vcpu, internal_breakpoint *bp) {
	uint8_t 				byte;
	int						ret;

	byte = bp->old_mem;
	ret = write_memory(g->mmu, bp->guest_addr_p, &byte, 1);

	remove_breakpoint(g, bp);

	return ret;
}

int svm_singlestep(internal_guest *g, internal_vcpu *vcpu) {
	uint64_t	old_rflags;
	int			ret;

	svm_internal_vcpu* svm_vcpu;
	svm_vcpu = to_svm_vcpu(vcpu);

	vcpu->state = VCPU_STATE_SINGLESTEP;

	old_rflags = svm_vcpu->vcpu_vmcb->rflags;
	svm_vcpu->vcpu_vmcb->rflags |= (uint64_t)1 << 8;

	vcpu->state = VCPU_STATE_SINGLESTEP;

	ret = svm_run_vcpu(vcpu, g);

	svm_vcpu->vcpu_vmcb->rflags = old_rflags;

	return ret;
}

int svm_handle_breakpoint(internal_guest *g, internal_vcpu *vcpu) {
	internal_breakpoint 	*bp;
	svm_internal_vcpu* 		svm_vcpu;
	gpa_t					phys_guest;
	gva_t					virt_guest;
	uint8_t 				byte;
	int						ret;
	
	svm_vcpu = to_svm_vcpu(vcpu);
	virt_guest = svm_vcpu->vcpu_vmcb->rip;

	printk(DBG "HIT BREAKPOINT AT: 0x%lx\n", svm_vcpu->vcpu_vmcb->rip);

	// First, look up which breakpoint belongs to that address

	if ((svm_vcpu->vcpu_vmcb->efer & EFER_LMA) && (svm_vcpu->vcpu_vmcb->cr0 & X86_CR0_PG)) {
		// Long mode
		bp = find_breakpoint_by_gva(g, virt_guest);

		// If we could not find a breakpoint with that virtual address,
		// iterate over all breakpoints and look if the physical addresses match.
		// If this is the case, insert the virtual address of the breakpoint (RIP)
		// into the internal_breakpoint structure.
		if (bp == NULL) {
			phys_guest = svm_mmu_gva_to_gpa(g, virt_guest);
			bp = find_breakpoint_by_gpa(g, phys_guest);

			// Only happens if the guest uses internally the int3 instruction.
			// The condition is only true, if there are int3 instructions which
			// are not set by the hypervisor.
			if (bp == NULL) {
				ret = -EFAULT;
				printk(DBG "No breapoint registered for address\n");
				goto err;
			}

			bp->guest_addr_v = virt_guest;
		} else {
			// Look if we filled in the physical address of a breakpoint.
			if (bp->guest_addr_p == 0) {
				phys_guest = svm_mmu_gva_to_gpa(g, virt_guest);
				bp->guest_addr_p = phys_guest;
			}
		}
	} else {
		// Protection mode non-paged
		phys_guest = virt_guest;
		bp = find_breakpoint_by_gpa(g, phys_guest);

		if (bp == NULL) {
			ret = -EFAULT;
			printk(DBG "No breapoint registered for address\n");
			goto err;
		}
	}

	vcpu->state = VCPU_STATE_BREAKPOINT;

	// Write the old byte at the breakpoint address
	byte = bp->old_mem;
	printk(DBG "writing at: 0x%lx, val: 0x%lx\n", bp->guest_addr_p, byte);
	ret = write_memory(g->mmu, bp->guest_addr_p, &byte, 1);
	if (ret) goto err;

	// Singlestep
	printk(DBG "Singlestep\n");

	ret = svm_singlestep(g, vcpu);
	if (ret) goto err;

	printk(DBG "Singlestep done\n");

	// Write the int3 again at the guest address
	byte = 0xcc;
	printk(DBG "writing at: 0x%lx, val: 0x%lx\n", bp->guest_addr_p, byte);
	ret = write_memory(g->mmu, bp->guest_addr_p, &byte, 1);
	if (ret) goto err;

	// Increase the converage counter
	if (g->fuzzing_coverage != (uint64_t*)NULL) {
		if (bp->num < (uint64_t)(g->fuzzing_coverage_size / sizeof(uint64_t))) g->fuzzing_coverage[bp->num]++;
	}

	vcpu->state = VCPU_STATE_BREAKPOINT;

	printk(DBG "BREAKPOINT done!\n");

err:
	return ret;
}

// This function will be called if AMD SVM support is detected
void init_svm_HYPEREYE_ops(void) {
	HYPEREYE_ops.run_vcpu 						= svm_run_vcpu;
    HYPEREYE_ops.create_arch_internal_vcpu 		= svm_create_arch_internal_vcpu;
	HYPEREYE_ops.simple_copy_arch_internal_vcpu 	= svm_simple_copy_arch_internal_vcpu;
	HYPEREYE_ops.destroy_arch_internal_vcpu 		= svm_destroy_arch_internal_vcpu,
    HYPEREYE_ops.create_arch_internal_guest 		= svm_create_arch_internal_guest;
	HYPEREYE_ops.simple_copy_arch_internal_guest = svm_simple_copy_arch_internal_guest;
    HYPEREYE_ops.destroy_arch_internal_guest 	= svm_destroy_arch_internal_guest;
	HYPEREYE_ops.set_vcpu_registers 				= svm_set_vcpu_registers;
    HYPEREYE_ops.get_vcpu_registers 				= svm_get_vcpu_registers;
    HYPEREYE_ops.set_memory_region 				= svm_set_memory_region;
	HYPEREYE_ops.map_page_attributes_to_arch		= svm_map_page_attributes_to_arch;
	HYPEREYE_ops.map_arch_to_page_attributes		= svm_map_arch_to_page_attributes;
	HYPEREYE_ops.init_mmu						= svm_init_mmu;
	HYPEREYE_ops.destroy_mmu						= svm_destroy_mmu;
	HYPEREYE_ops.mmu_walk_available				= svm_mmu_walk_available;
	HYPEREYE_ops.mmu_walk_next					= svm_mmu_walk_next;
	HYPEREYE_ops.mmu_walk_init					= svm_mmu_walk_init;
	HYPEREYE_ops.mmu_gva_to_gpa					= svm_mmu_gva_to_gpa;
	HYPEREYE_ops.add_breakpoint_p				= svm_add_breakpoint_p;
	HYPEREYE_ops.add_breakpoint_v				= svm_add_breakpoint_v;
	HYPEREYE_ops.remove_breakpoint				= svm_remove_breakpoint;
	HYPEREYE_ops.singlestep						= svm_singlestep;
	HYPEREYE_ops.handle_mmio						= x86_handle_mmio;
	HYPEREYE_ops.register_kvm_record_handler 	= svm_register_kvm_record_handler;
	HYPEREYE_ops.deregister_kvm_record_handler 	= svm_deregister_kvm_record_handler;

	HYPEREYE_initialized = 1;
}