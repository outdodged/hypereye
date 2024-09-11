#pragma once

#include <memory.h>
#include <guest.h>
#include <HYPEREYE_defs.h>

#include <stddef.h>
#include <linux/list.h>

void* 	svm_create_arch_internal_vcpu(internal_guest *g, internal_vcpu* vcpu);
void*   svm_simple_copy_arch_internal_vcpu(internal_guest *copy_g, internal_vcpu *vcpu, internal_vcpu* copy_vcpu);
int 	svm_destroy_arch_internal_vcpu(internal_vcpu *vcpu);
void* 	svm_create_internal_guest(void);
void*   simple_copy_arch_internal_guest(internal_guest *g, internal_guest *copy_g);
void 	svm_destroy_internal_guest(internal_guest *g);
void 	svm_set_vcpu_registers(internal_vcpu *vcpu, user_arg_registers *regs);
void 	svm_get_vcpu_registers(internal_vcpu *vcpu, user_arg_registers *regs);
void 	svm_set_memory_region(internal_guest *g, internal_memory_region *memory_region);
int     svm_handle_breakpoint(internal_guest *g, internal_vcpu *vcpu);

void	init_svm_HYPEREYE_ops(void);