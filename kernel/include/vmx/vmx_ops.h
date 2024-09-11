#pragma once

#include <memory.h>
#include <guest.h>
#include <HYPEREYE_defs.h>

void* 	vmx_create_arch_internal_vcpu(internal_guest *g, internal_vcpu* vcpu);
void*   vmx_simple_copy_arch_internal_vcpu(internal_guest *copy_g, internal_vcpu *vcpu, internal_vcpu* copy_vcpu);
int 	vmx_destroy_arch_internal_vcpu(internal_vcpu *vcpu);
void* 	vmx_create_internal_guest(void);
void 	vmx_destroy_internal_guest(internal_guest *g);
void 	vmx_set_vcpu_registers(internal_vcpu *vcpu, user_arg_registers *regs);
void 	vmx_get_vcpu_registers(internal_vcpu *vcpu, user_arg_registers *regs);
void 	vmx_set_memory_region(internal_guest *g, internal_memory_region *memory_region);
int     vmx_handle_breakpoint(internal_guest *g, internal_vcpu *vcpu);

void	init_vmx_HYPEREYE_ops(void);