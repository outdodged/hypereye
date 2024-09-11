#include <svm/svm.h>
#include <svm/svm_ops.h>
#include <ioctl.h>
#include <stddef.h>
#include <memory.h>
#include <HYPEREYE.h>
#include <x86/x86.h>

#include <asm/msr-index.h>
#include <asm/msr.h>
#include <linux/smp.h>

inline svm_internal_guest* to_svm_guest(internal_guest *g) {
	return (svm_internal_guest*)(g->arch_internal_guest);
}

inline svm_internal_vcpu* to_svm_vcpu(internal_vcpu *vcpu){
	return (svm_internal_vcpu*)(vcpu->arch_internal_vcpu);
}

uint64_t svm_generate_asid(void) {
	// TODO
	return 1;
}

void svm_flush_tlb_by_asid(internal_vmcb *v) {
	v->tlb_control = TLB_FLUSH_THIS;
}

int svm_reset_vcpu(svm_internal_vcpu *svm_vcpu, internal_guest *g) {
	svm_internal_guest 	*svm_g;

	TEST_PTR(svm_vcpu, svm_internal_vcpu*,, ERROR)
	TEST_PTR(svm_vcpu->vcpu_vmcb, internal_vmcb*,, ERROR)

	TEST_PTR(g, internal_guest*,, ERROR)
	svm_g = to_svm_guest(g);
	TEST_PTR(svm_g, svm_internal_guest*,, ERROR)
	
	svm_vcpu->vcpu_vmcb->guest_asid = svm_generate_asid();

	svm_vcpu->vcpu_vmcb->cs.selector = 0xf000;
	svm_vcpu->vcpu_vmcb->cs.base = 0x0;
	svm_vcpu->vcpu_vmcb->cs.limit = 0xffffffff;
	svm_vcpu->vcpu_vmcb->cs.attrib = 0x049b;
	svm_vcpu->vcpu_vmcb->ds.limit = 0xffffffff;
	svm_vcpu->vcpu_vmcb->ds.attrib = 0x0093;
	svm_vcpu->vcpu_vmcb->es.limit = 0xffffffff;
	svm_vcpu->vcpu_vmcb->es.attrib = 0x0093;
	svm_vcpu->vcpu_vmcb->fs.limit = 0xffffffff;
	svm_vcpu->vcpu_vmcb->fs.attrib = 0x0093;
	svm_vcpu->vcpu_vmcb->gs.limit = 0xffffffff;
	svm_vcpu->vcpu_vmcb->gs.attrib = 0x0093;
	svm_vcpu->vcpu_vmcb->ss.limit = 0xffffffff;
	svm_vcpu->vcpu_vmcb->ss.attrib = 0x0093;

	svm_vcpu->vcpu_vmcb->cr0 = X86_CR0_ET | X86_CR0_PE;
	svm_vcpu->vcpu_vmcb->cr3 = 0;
	svm_vcpu->vcpu_vmcb->cr4 = 0;

	svm_vcpu->vcpu_vmcb->rflags = 0x02;

	svm_vcpu->vcpu_vmcb->interrupt_control = 1 << 24;

	svm_vcpu->vcpu_vmcb->gdtr.limit = 0xffff;
	svm_vcpu->vcpu_vmcb->idtr.limit = 0xffff;

	svm_vcpu->vcpu_vmcb->dr6 = 0xffff0ff0;

	svm_vcpu->vcpu_vmcb->efer = EFER_SVME;
	
	// Enable nested paging
	svm_vcpu->vcpu_vmcb->nested_and_sec_control |= 1;

	// Intercept all possible exceptions and instructions
	svm_vcpu->vcpu_vmcb->intercept_exceptions = 0xffffffff;
	svm_vcpu->vcpu_vmcb->intercept = 0xffffffffffffff00;

	// Set the nested pagetables
	svm_vcpu->vcpu_vmcb->n_cr3 = __pa(svm_g->nested_pagetables);

	svm_vcpu->vcpu_vmcb->msrprm_base_pa = __pa(svm_g->msr_permission_map);

	svm_vcpu->vcpu_vmcb->vmcb_clean = VMCB_DIRTY_ALL_DIRTY;

	svm_flush_tlb_by_asid(svm_vcpu->vcpu_vmcb);
	
	return 0;
}

u64 msr_rdmsr(u32 msr) {
	u32 a, d;
	__asm__ __volatile__("rdmsr" : "=a"(a), "=d"(d) : "c"(msr) : "memory");
	return a | ((u64) d << 32);
}

uint64_t map_to_pagefault_reason(uint64_t npf_exitinfo) {
	uint64_t					pagefault_reason = 0;

	printk(DBG "npf_exitinfo: 0x%llx\n", npf_exitinfo);

	if ((npf_exitinfo & NPF_NOT_PRESENT) == 0) {
		printk(DBG "p\n");
	 	pagefault_reason |= PAGEFAULT_NON_PRESENT;
	}
	if (npf_exitinfo & NPF_WRITE_ACCESS) {
		printk(DBG "w\n");
		pagefault_reason |= PAGEFAULT_WRITE;
	}
	if (npf_exitinfo & NPF_CODE_ACCESS) {
		printk(DBG "e\n");
		pagefault_reason |= PAGEFAULT_EXEC;
	}
	if ((npf_exitinfo & NPF_CODE_ACCESS) == 0 
		&& (npf_exitinfo & NPF_WRITE_ACCESS) == 0
		&& (npf_exitinfo & NPF_RESERVED) == 0) {
		printk(DBG "r\n");
		pagefault_reason |= PAGEFAULT_READ;
	}

	return pagefault_reason;
}

void svm_handle_vmexit(internal_vcpu *vcpu, internal_guest *g) {
	svm_internal_vcpu 			*svm_vcpu;

	svm_vcpu = to_svm_vcpu(vcpu);

	// We set clean bits as needed.
	svm_vcpu->vcpu_vmcb->vmcb_clean = VMCB_DIRTY_ALL_CLEAN;

	printk("\n");
	printk(DBG "#VMEXIT exitcode: 0x%lx, exitinfo1: 0x%lx, exitinfo2: 0x%lx\n", (unsigned long)svm_vcpu->vcpu_vmcb->exitcode, (unsigned long)svm_vcpu->vcpu_vmcb->exitinfo1, (unsigned long)svm_vcpu->vcpu_vmcb->exitinfo2);
	printk("\n");

	switch (svm_vcpu->vcpu_vmcb->exitcode) {
		case VMEXIT_NPF:
			// Only handle pagefaults in the nested pagetables
			if ((svm_vcpu->vcpu_vmcb->exitinfo1 & NPF_IN_VMM_PAGE) != 0) {
				handle_pagefault(g, vcpu, __va(svm_vcpu->vcpu_vmcb->n_cr3), svm_vcpu->vcpu_vmcb->exitinfo2, map_to_pagefault_reason(svm_vcpu->vcpu_vmcb->exitinfo1));
				svm_flush_tlb_by_asid(svm_vcpu->vcpu_vmcb);
			}
			break;
		case VMEXIT_EXCP_BASE ... (VMEXIT_EXCP_BASE + 32):
			// Reflect all exceptions in which we are not interested in

			// Singlestepping
			if (svm_vcpu->vcpu_vmcb->exitcode == VMEXIT_EXCP_BASE + EXCEPTION_DB) {
				/*if (vcpu->state == VCPU_STATE_SINGLESTEP) {
					vcpu->state = VCPU_STATE_PAUSED;
				}*/
				break;
			}

			// Breakpoint handling
			if (svm_vcpu->vcpu_vmcb->exitcode == VMEXIT_EXCP_BASE + EXCEPTION_BP) {
				if (!svm_handle_breakpoint(g, vcpu)) break;
			}

			svm_reflect_exception(vcpu);
			break;
		case VMEXIT_MSR:
			// MSR access handling
			if (svm_vcpu->vcpu_vmcb->exitinfo1) {
				svm_handle_msr_access_write(vcpu);
			} else {
				svm_handle_msr_access_read(vcpu);
			}
			break;
		case VMEXIT_IOIO:
			svm_handle_io(vcpu);
			svm_forward_rip(vcpu);
			break;
		case VMEXIT_INVD:
		case VMEXIT_SHUTDOWN:
		case VMEXIT_VMRUN:
		case VMEXIT_VMMCALL:
		case VMEXIT_VMLOAD:
		case VMEXIT_VMSAVE:
		case VMEXIT_STGI:
		case VMEXIT_CLGI:
		case VMEXIT_SKINIT:
		case VMEXIT_ICEBP:
		case VMEXIT_INVLPGA:
		case VMEXIT_INVLPGB:
			// Skip these instructions and generate a #UD in the guest.
			svm_inject_event(vcpu, EVENT_INJECT_TYPE_EXCEPTION, EXCEPTION_UD, 0);
			svm_forward_rip(vcpu);
			break;
		default:
			printk(DBG "Unknown exit code: 0x%llx, exitinfo1: 0x%llx, exitinfo2: 0x%llx\n", svm_vcpu->vcpu_vmcb->exitcode, svm_vcpu->vcpu_vmcb->exitinfo1, svm_vcpu->vcpu_vmcb->exitinfo2);
	}
}

void svm_run_vcpu_internal(void *info) {
	internal_vcpu 				*vcpu;
	svm_internal_vcpu 			*svm_vcpu;
	uint64_t 					efer;
	uint64_t 					vm_hsave_pa;
	uint64_t 					host_fs_base, host_gs_base;

	vcpu = (internal_vcpu*) info;
	svm_vcpu = to_svm_vcpu(vcpu);
	
	if (get_cpu() == vcpu->physical_core) {
		printk(DBG "Running on CPU: %d\n", smp_processor_id());
		
		if ((msr_rdmsr(MSR_EFER) & EFER_SVME) != 0) {
			vcpu->state = VCPU_STATE_FAILED;
			return;
		}
		
		vcpu->state = VCPU_STATE_RUNNING;
		
		vm_hsave_pa = __pa(svm_vcpu->host_vmcb);
		wrmsrl_safe(MSR_VM_HSAVE_PA, vm_hsave_pa);
		
		efer = msr_rdmsr(MSR_EFER);
		wrmsrl_safe(MSR_EFER, efer | EFER_SVME);

		host_fs_base = msr_rdmsr(MSR_FS_BASE);
		host_gs_base = msr_rdmsr(MSR_GS_BASE);

		svm_run_vcpu_asm(__pa(svm_vcpu->vcpu_vmcb), __pa(svm_vcpu->host_vmcb), (unsigned long)(svm_vcpu->vcpu_regs));

		wrmsrl_safe(MSR_FS_BASE, host_fs_base);
		wrmsrl_safe(MSR_GS_BASE, host_gs_base);
		
		//vcpu->state = VCPU_STATE_PAUSED;

		if (svm_vcpu->vcpu_vmcb->exitcode == VMEXIT_INVALID) vcpu->state = VCPU_STATE_FAILED;

		asm volatile ("stgi");

		efer = msr_rdmsr(MSR_EFER);
		wrmsrl_safe(MSR_EFER, efer & ~EFER_SVME);
	}
	put_cpu();
}

int svm_run_vcpu(internal_vcpu *vcpu, internal_guest *g) {
	svm_internal_vcpu 			*svm_vcpu;
	int							i = 0;

	TEST_PTR(vcpu, internal_vcpu*,, ERROR)
	svm_vcpu = to_svm_vcpu(vcpu);
	TEST_PTR(svm_vcpu, svm_internal_vcpu*,, ERROR)
	TEST_PTR(svm_vcpu->vcpu_vmcb, internal_vmcb*,, ERROR)
	TEST_PTR(svm_vcpu->host_vmcb, internal_vmcb*,, ERROR)

	if (vcpu != NULL) {
		while ((vcpu->state == VCPU_STATE_CREATED ||
				vcpu->state == VCPU_STATE_PAUSED ||
				svm_vcpu->vcpu_vmcb->exitcode == VMEXIT_NPF ||
				vcpu->state == VCPU_STATE_BREAKPOINT ||
				vcpu->state == VCPU_STATE_SINGLESTEP)
				&& vcpu->state != VCPU_STATE_FAILED
				&& i < 100) {
			//printk(DBG "vcpu state: 0x%lx", vcpu->state);
			on_each_cpu((void*)svm_run_vcpu_internal, vcpu, 1);
			svm_handle_vmexit(vcpu, g);
			i++;
		}
		vcpu->state = VCPU_STATE_PAUSED;
	
		return 0;
	} else {
		return -EFAULT;
	}
}

int svm_check_support(void) {
	unsigned int cpuid_ret_val;
	__asm__ ("cpuid; movl %%ecx, %0;" : "=r"(cpuid_ret_val));
	if (cpuid_ret_val && 0x80000001 == 0){
		printk(DBG "AMD SVM not supported\n");
		return -EFAULT;
	}

	__asm__ ("cpuid; movl %%edx, %0;" : "=r"(cpuid_ret_val));
	if (cpuid_ret_val && 0x8000000A == 0){
		printk(DBG "AMD SVM disabled at bios\n");
		return -EFAULT;
	}

	return 0;
}

void svm_forward_rip(internal_vcpu *vcpu) {
	svm_internal_vcpu 			*svm_vcpu;

	svm_vcpu = to_svm_vcpu(vcpu);
	svm_vcpu->vcpu_vmcb->rip += svm_vcpu->vcpu_vmcb->insn_len;
	svm_vcpu->vcpu_vmcb->insn_len = 0;
}

int svm_set_msrpm_permission(uint8_t *msr_permission_map, uint32_t msr, int read, int write) {
	unsigned int idx; // the index in the table
	unsigned int offset; // the offset of the msr in a single byte

	if (read != 0 || read != 1) return -EINVAL;
	if (write != 0 || write != 1) return -EINVAL;

	idx = (int)(msr / 4);
	offset = 2 * (msr & 0xf);

	msr_permission_map[idx] = msr_permission_map[idx] & ~(0b11 << offset);

	msr_permission_map[idx] = msr_permission_map[idx] | (read << offset);
	msr_permission_map[idx] = msr_permission_map[idx] | (write << (offset + 2));

	return 0;
}

void svm_inject_event(internal_vcpu *vcpu, unsigned int type, uint8_t vector, uint32_t errorcode) {
	svm_internal_vcpu 			*svm_vcpu;

	svm_vcpu = to_svm_vcpu(vcpu);

	svm_vcpu->vcpu_vmcb->event_inject = vector | (type << 8) | EVENT_INJECT_VALID;

	// Check if this vector pushes an errorcode onto the stack.
	if (vector == 10 || vector == 11 || vector == 12 || vector == 13 || vector == 14) {
		svm_vcpu->vcpu_vmcb->event_inject_error = errorcode;
		svm_vcpu->vcpu_vmcb->event_inject |= EVENT_INJECT_ERROR_VALID;
	} else {
		svm_vcpu->vcpu_vmcb->event_inject_error = 0;
	}
}

void svm_handle_msr_access_write(internal_vcpu *vcpu) {
	svm_internal_vcpu 			*svm_vcpu;

	svm_vcpu = to_svm_vcpu(vcpu);

	// Currently, we allowed access to all necessary MSRs. Inject a #GP
	svm_inject_event(vcpu, EVENT_INJECT_TYPE_EXCEPTION, EXCEPTION_GP, 0);

}

void svm_handle_msr_access_read(internal_vcpu *vcpu) {
	svm_internal_vcpu 			*svm_vcpu;

	svm_vcpu = to_svm_vcpu(vcpu);

	// Currently, we allowed access to all necessary MSRs. Inject a #GP
	svm_inject_event(vcpu, EVENT_INJECT_TYPE_EXCEPTION, EXCEPTION_GP, 0);
}

void svm_handle_io(internal_vcpu *vcpu) {
	svm_internal_vcpu 			*svm_vcpu;
	int							in;
	uint32_t					rep;
	uint32_t					op_size;
	uint16_t					port;
	uint32_t					eax;

	svm_vcpu = to_svm_vcpu(vcpu);

	in 		= (svm_vcpu->vcpu_vmcb->exitinfo1 & (1 << 0)) ? 1 : 0;
	rep 	= (svm_vcpu->vcpu_vmcb->exitinfo1 & (1 << 3)) ? 1 : 0;
	op_size	= (svm_vcpu->vcpu_vmcb->exitinfo1 >> 4) & 0x7;
	port 	= (uint16_t)(svm_vcpu->vcpu_vmcb->exitinfo1 >> 16);
	eax 	= (uint32_t)(svm_vcpu->vcpu_vmcb->rax);

	x86_handle_io(in, op_size, port, &eax);
	if (in) svm_vcpu->vcpu_vmcb->rax = eax;
	svm_forward_rip(vcpu);
}

void svm_reflect_exception(internal_vcpu *vcpu) {
	svm_internal_vcpu 			*svm_vcpu;
	uint32_t					vector;
	uint32_t					errorcode;

	svm_vcpu 	= to_svm_vcpu(vcpu);
	vector 		= svm_vcpu->vcpu_vmcb->exitcode - VMEXIT_EXCP_BASE;
	errorcode 	= 0;

	switch (vector) {
		case EXCEPTION_DE  : 
			break;
		case EXCEPTION_DB  : 
			break;
		case EXCEPTION_NMI : 
			break;
		case EXCEPTION_BP  : 
			break;
		case EXCEPTION_OF  : 
			break;
		case EXCEPTION_BR  : 
			break;
		case EXCEPTION_UD  : 
			break;
		case EXCEPTION_NM  : 
			break;
		case EXCEPTION_DF  : 
			break;
		case EXCEPTION_TS  : 
			// TODO: None?
			errorcode = svm_vcpu->vcpu_vmcb->exitinfo1;
			break;
		case EXCEPTION_NP  : 
			errorcode = svm_vcpu->vcpu_vmcb->exitinfo1;
			break;
		case EXCEPTION_SS  :
			errorcode = svm_vcpu->vcpu_vmcb->exitinfo1; 
			break;
		case EXCEPTION_GP  : 
			errorcode = svm_vcpu->vcpu_vmcb->exitinfo1;
			break;
		case EXCEPTION_PF  : 
			errorcode = svm_vcpu->vcpu_vmcb->exitinfo1;
			// Intercept is tested before CR2 in the guest is written.
			svm_vcpu->vcpu_vmcb->cr2 = svm_vcpu->vcpu_vmcb->exitinfo2;
			break;
		case EXCEPTION_MF  : 
			break;
		case EXCEPTION_AC  : 
			errorcode = 0;
			break;
		case EXCEPTION_MC  : 
			break;
		case EXCEPTION_XF  : 
			break;
		case EXCEPTION_HV  : 
			break;
		case EXCEPTION_VC  : 
			break;
		case EXCEPTION_SX  : 
			break;
	}

	svm_inject_event(vcpu, EVENT_INJECT_TYPE_EXCEPTION, vector, errorcode);
	svm_forward_rip(vcpu);
}