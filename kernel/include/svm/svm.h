#pragma once

#include <svm/vmcb.h>
#include <guest.h>
#include <HYPEREYE_defs.h>

struct svm_internal_vcpu {
	internal_vmcb*	vcpu_vmcb;
	internal_vmcb*	host_vmcb;
	svm_gp_regs*		vcpu_regs;
	uint64_t		host_fs_base;
	uint64_t		host_gs_base;
} typedef svm_internal_vcpu;

struct svm_internal_guest {
	uint64_t		highest_phys_addr; // contains the number of bytes the guest has available as memory
	uint64_t		used_cores;
	
	void*			nested_pagetables; // map guest physical to host physical memory
	
	// intercept reasons set in the VMCB for all VCPUs
	uint32_t		intercept_exceptions;
	uint64_t		intercept;
	
	// the MSR and I/O permission maps will be used by all VPCUs by the guest
	uint8_t* 		msr_permission_map;
	uint8_t* 		io_permission_map;
} typedef svm_internal_guest;

inline svm_internal_guest* to_svm_guest(internal_guest* g);
inline svm_internal_vcpu*  to_svm_vcpu(internal_vcpu* g);

// SVM-related functions
void svm_handle_vmexit(internal_vcpu *current_vcpu, internal_guest *g);
int  svm_run_vcpu(internal_vcpu *vcpu, internal_guest *g);
int  svm_reset_vcpu(svm_internal_vcpu *svm_vcpu, internal_guest *g);
int  svm_check_support(void);
int  svm_set_msrpm_permission(uint8_t *msr_permission_map, uint32_t msr, int read, int write);
void svm_forward_rip(internal_vcpu *vcpu);
void svm_inject_event(internal_vcpu *vcpu, unsigned int type, uint8_t vector, uint32_t errorcode);
void svm_handle_msr_access_write(internal_vcpu *vcpu);
void svm_handle_msr_access_read(internal_vcpu *vcpu);
void svm_handle_io(internal_vcpu *vcpu);
void svm_reflect_exception(internal_vcpu *vcpu);

// KVM-related functions
void svm_register_kvm_record_handler(void);
void svm_deregister_kvm_record_handler(void);

extern void svm_run_vcpu_asm(unsigned long phys_addr_guest_vmcb, unsigned long phys_addr_host_vmcb, unsigned long saved_guest_regs_addr);