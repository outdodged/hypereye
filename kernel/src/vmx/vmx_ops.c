#include <vmx/vmx_ops.h>

#include <linux/slab.h>

void* vmx_create_arch_internal_guest(internal_guest *g) {
	vmx_internal_guest	*vmx_g;

	svm_g = (svm_internal_guest*) kzalloc(sizeof(internal_guest), GFP_KERNEL);
	TEST_PTR(svm_g, svm_internal_guest*,,NULL)

	// Get the root for the nested pagetables from the MMU.
	svm_g->nested_pagetables = g->mmu->base;

	return (void*)vmx_g;
}

void* vmx_create_arch_internal_vcpu(internal_guest *g, internal_vcpu* vcpu) {
	vmx_internal_guest	*vmx_g;
	vmx_internal_vcpu	*vmx_vcpu;

	TEST_PTR(g, internal_guest*,, NULL)
	svm_g = to_vmx_guest(g);
	TEST_PTR(vmx_g, vmx_internal_guest*,, NULL)

	vmx_vcpu = kzalloc(PAGE_SIZE, GFP_KERNEL);
	vmx_vcpu->vmcs_region  = kzalloc(PAGE_SIZE, GFP_KERNEL);
	vmx_vcpu->vmxon_region = kzalloc(PAGE_SIZE, GFP_KERNEL);
	vmx_vcpu->vcpu_regs    = kzalloc(sizeof(vmx_gp_regs), GFP_KERNEL);
	vmx_vcpu->vmm_stack    = kzalloc(PAGE_SIZE, GFP_KERNEL);

	TEST_PTR(vmx_vcpu->vmcs_region, internal_vmcb*, kfree(vmx_vcpu), NULL);
	TEST_PTR(vmx_vcpu->vmxon_region, internal_vmcb*, kfree(vmx_vcpu); kfree(vmx_vcpu->vmcs_region), NULL);
	TEST_PTR(vmx_vcpu->vcpu_regs, vmx_gp_regs*, kfree(vmx_vcpu); kfree(vmx_vcpu->vmcs_region); kfree(vmx_vcpu->vmxon_region), NULL);
	TEST_PTR(vmx_vcpu->vmm_stack, vmx_gp_regs*, kfree(vmx_vcpu); kfree(vmx_vcpu->vmcs_region); kfree(vmx_vcpu->vmxon_region); kfree(vmx_vcpu->vcpu_regs), NULL);

	vmx_reset_vcpu(g, vmx_vcpu);

	return (void*)vmx_vcpu;
}

void* vmx_simple_copy_arch_internal_vcpu(internal_guest *copy_g, internal_vcpu *vcpu, internal_vcpu* copy_vcpu) {

}

int vmx_destroy_arch_internal_vcpu(internal_vcpu *vcpu) {

}

void vmx_destroy_internal_guest(internal_guest *g) {
	vmx_internal_guest		*vmx_g;

	TEST_PTR(g, internal_guest*,,)
	vmx_g = to_svm_guest(g);

	if (vmx_g != NULL) {
		kfree(vmx_g);
	}
}

void vmx_set_vcpu_registers(internal_vcpu *vcpu, user_arg_registers *regs) {

}

void vmx_get_vcpu_registers(internal_vcpu *vcpu, user_arg_registers *regs) {

}

void vmx_set_memory_region(internal_guest *g, internal_memory_region *memory_region) {

}

int vmx_handle_breakpoint(internal_guest *g, internal_vcpu *vcpu) {

}

void init_vmx_HYPEREYE_ops(void) {
    /*HYPEREYE_ops.run_vcpu 						= vmx_run_vcpu;
    HYPEREYE_ops.create_arch_internal_vcpu 		= vmx_create_arch_internal_vcpu;
	HYPEREYE_ops.simple_copy_arch_internal_vcpu 	= vmx_simple_copy_arch_internal_vcpu;
	HYPEREYE_ops.destroy_arch_internal_vcpu 		= vmx_destroy_arch_internal_vcpu,
    HYPEREYE_ops.create_arch_internal_guest 		= vmx_create_arch_internal_guest;
	HYPEREYE_ops.simple_copy_arch_internal_guest = vmx_simple_copy_arch_internal_guest;
    HYPEREYE_ops.destroy_arch_internal_guest 	= vmx_destroy_arch_internal_guest;
	HYPEREYE_ops.set_vcpu_registers 				= vmx_set_vcpu_registers;
    HYPEREYE_ops.get_vcpu_registers 				= vmx_get_vcpu_registers;
    HYPEREYE_ops.set_memory_region 				= ept_set_memory_region;
	HYPEREYE_ops.map_page_attributes_to_arch		= ept_map_page_attributes_to_arch;
	HYPEREYE_ops.map_arch_to_page_attributes		= ept_map_arch_to_page_attributes;
	HYPEREYE_ops.init_mmu						= ept_init_mmu;
	HYPEREYE_ops.destroy_mmu						= ept_destroy_mmu;
	HYPEREYE_ops.mmu_walk_available				= ept_mmu_walk_available;
	HYPEREYE_ops.mmu_walk_next					= ept_mmu_walk_next;
	HYPEREYE_ops.mmu_walk_init					= ept_mmu_walk_init;
	HYPEREYE_ops.mmu_gva_to_gpa					= ept_mmu_gva_to_gpa;
	HYPEREYE_ops.add_breakpoint_p				= vmx_add_breakpoint_p;
	HYPEREYE_ops.add_breakpoint_v				= vmx_add_breakpoint_v;
	HYPEREYE_ops.remove_breakpoint				= vmx_remove_breakpoint;
	HYPEREYE_ops.singlestep						= vmx_singlestep;*/

	HYPEREYE_initialized = 1;
}