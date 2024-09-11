#include <vmx/vmx.h>
#include <vmx/ept.h>
#include <utils.h>

#include <asm/segment.h>
#include <asm/special_insns.h>

inline vmx_internal_guest* to_vmx_guest(internal_guest *g) {
	return (vmx_internal_guest*)(g->arch_internal_guest);
}

inline vmx_internal_vcpu* to_svm_vcpu(internal_vcpu *vcpu) {
	return (vmx_internal_vcpu*)(vcpu->arch_internal_vcpu);
}

void vmx_vmxon_internal(void *info) {
	internal_vcpu 				*vcpu;
	vmx_internal_vcpu			*vmx_vcpu;

	vcpu = (internal_vcpu*) 	info;
	vmx_vcpu = to_vmx_vcpu(vcpu);

	if (get_cpu() == vcpu->physical_core) {
		printk(DBG "Running on CPU: %d\n", smp_processor_id());
		int ret = vmx_vmxon(vmx_vcpu->vmxon_region);

		if (ret != 0) {
			printk(DBG "Error executing vmxon.");
		}
	}
}

int vmx_reset_vcpu(internal_guest *g, vmx_internal_vcpu *vmx_vcpu) {
    uint32_t                      msr_vmx_basic;
    vmx_vm_entry_controls         vm_entry_controls;
    vmx_primary_vm_exit_controls  primary_vm_exit_controls;
    vmx_pin_based_vm_exec_control pin_based_vm_exec_control;
    vmx_primary_vm_exec_control   primary_vm_exec_control;
    vmx_secondary_vm_exec_control secondary_vm_exec_control;

    vmx_vcpu->launched = 0;

    msr_vmx_basic = msr_rdmsr(MSR_FS_BASE);

    // Initialize the vmxon region
    vmx_vcpu->vmxon_region->vmcs_revision_identifier = msr_vmx_basic;

    on_each_cpu((void*)vmx_vmxon_internal, vcpu, 1);

    // Set EPT base
    vmx_vmwrite(EPT_POINTER, ept_get_config(g->mmu));

    // Initialize the vmcs region
    vmx_vcpu->vmcs_region->header.vmcs_revision_identifier = msr_vmx_basic;
    vmx_vcpu->vmcs_region->header.shadow_vmcs_indicator = 0;

    // Set registers
    vmx_vmwrite(GUEST_RSP, 0x0);
    vmx_vmwrite(GUEST_RIP, 0x0);

    vmx_vmwrite(GUEST_CR0, X86_CR0_ET | X86_CR0_PE);
    vmx_vmwrite(GUEST_CR3, 0x0);
    vmx_vmwrite(GUEST_CR4, 0x0);

    vmx_vmwrite(GUEST_RFLAGS, 0x02);

    vmx_vmwrite(GUEST_CS_SELECTOR, 0xf000);
    vmx_vmwrite(GUEST_CS_BASE,     0x0);
    vmx_vmwrite(GUEST_CS_LIMIT,    0xffffffff);
    vmx_vmwrite(GUEST_DS_LIMIT,    0xffffffff);
    vmx_vmwrite(GUEST_ES_LIMIT,    0xffffffff);
    vmx_vmwrite(GUEST_FS_LIMIT,    0xffffffff);
    vmx_vmwrite(GUEST_GS_LIMIT,    0xffffffff);
    vmx_vmwrite(GUEST_SS_LIMIT,    0xffffffff);

    vmx_vmwrite(GUEST_GDTR_LIMIT,    0xffff);
    vmx_vmwrite(GUEST_IDTR_LIMIT,    0xffff);

    // Host state to restore upon VM exit

    // Host: Segment selectors
    uint16_t host_cs_selector;
    savesegment(cs, host_cs_selector);
    vmx_vmwrite(HOST_CS_SELECTOR, host_cs_selector);

    uint16_t host_ds_selector;
    savesegment(cs, host_ds_selector);
    vmx_vmwrite(HOST_DS_SELECTOR, host_ds_selector);

    uint16_t host_es_selector;
    savesegment(cs, host_es_selector);
    vmx_vmwrite(HOST_ES_SELECTOR, host_es_selector);

    uint16_t host_fs_selector;
    savesegment(cs, host_fs_selector);
    vmx_vmwrite(HOST_FS_SELECTOR, host_fs_selector);

    uint16_t host_gs_selector;
    savesegment(cs, host_gs_selector);
    vmx_vmwrite(HOST_GS_SELECTOR, host_gs_selector);

    uint16_t host_ss_selector;
    savesegment(cs, host_ss_selector);
    vmx_vmwrite(HOST_SS_SELECTOR, host_ss_selector);

    uint16_t host_ss_selector;
    savesegment(cs, host_ss_selector);
    vmx_vmwrite(HOST_SS_SELECTOR, host_ss_selector);

    // Host: Segment bases
    uint64_t host_fs_base = read_msr(MSR_FS_BASE);
    vmx_vmwrite(HOST_FS_BASE, host_fs_base);

    uint64_t host_gs_base = read_msr(MSR_GS_BASE);
    vmx_vmwrite(HOST_GS_BASE, host_gs_base);

    vmx_vmwrite(HOST_TR_BASE, (uint64_t)&get_cpu_entry_area(cpu)->tss.x86_tss);

    vmx_vmwrite(HOST_GDTR_BASE, (uint64_t)get_current_gdt_ro());

    // Host: Control registers
    vmx_vmwrite(HOST_CR0, read_cr0());
    vmx_vmwrite(HOST_CR3, __read_cr3());
    vmx_vmwrite(HOST_CR4, __read_cr4());

    // Used on return after vm exit
    vmx_vmwrite(HOST_RSP, (uint64_t))vmx_cpu->vmm_stack));
    vmx_vmwrite(HOST_RIP, (uint64_t)vmx_vm_exit);

    // Entry control
    vm_entry_controls.all = 0;
    vm_entry_controls.bits.ia32e_mode_guest = 1;
    vmx_vmwrite(VM_ENTRY_CONTROLS, vm_entry_controls.all);

    // Primary exit control
    primary_vm_exit_controls.all = 0;
    primary_vm_exit_controls.bits.host_addr_space_size = 1;
    vmx_vmwrite(VM_EXIT_CONTROLS, primary_vm_exit_controls.all);

    // Pin-based control
    pin_based_vm_exec_control.all = 0;
    vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, pin_based_vm_exec_control.all);

    // Primary VM execution control
    primary_vm_exec_control.all = 0;
    primary_vm_exec_control.bits.use_msr_bitmaps = 1;
    primary_vm_exec_control.bits.activate_secondary_controls = 1;

    primary_vm_exec_control.bits.hlt_exiting = 1;

    vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, primary_vm_exec_control.all)

    // Secondary VM execution control
    secondary_vm_exec_control.all = 0;
    vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, secondary_vm_exec_control.all);

    return 0;
}

void enable_vmx() {

}

void disable_vmx() {

}

void vmx_run_vcpu(vmx_internal_vcpu *vmx_vcpu) {
    if (vmx_vcpu->launched == 0) {
        uint64_t ret = vmx_run_vcpu_asm_vmlaunch(vmx_vcpu->vmcs_region, *vmx_vcpu->vcpu_regs);
        if (ret != 0) {
            printk(DBG "vmlaunch failed!\n");
        }
        vmx_vcpu->launched = 1;
    } else {
        uint64_t ret = vmx_run_vcpu_asm_vmresume(vmx_vcpu->vmcs_region, *vmx_vcpu->vcpu_regs);
        if (ret != 0) {
            printk(DBG "vmlaunch failed!\n");
        }
    }
}

void vmx_handle_vm_exit(vmx_gp_regs *guest_regs) {
    vmx_exit_reason exit_reason;

    uint32_t current_core = get_cpu();

    // First, find the correct vcpu struct by using the core ID.
    exit_reason.all = vmx_vmread(VM_EXIT_REASON);
    printk(DBG "exit reason: 0x%lx\n", (unsigned long)exit_reason.bits.exit_reason);

    switch(exit_reason.bits.exit_reason) {
        case VM_EXIT_REASON_VMCALL:
        case VM_EXIT_REASON_VMCLEAR:
        case VM_EXIT_REASON_VMLAUNCH:
        case VM_EXIT_REASON_VMPTRLD:
        case VM_EXIT_REASON_VMPTRST:
        case VM_EXIT_REASON_VMRESUME:
        case VM_EXIT_REASON_VMXON:
        case VM_EXIT_REASON_VMXOFF:
        case VM_EXIT_REASON_INVEPT:
        case VM_EXIT_REASON_INVVPID:
            break;
        case VM_EXIT_REASON_MSR_READ:
            break;
        case VM_EXIT_REASON_MSR_WRITE:
            break;
        case VM_EXIT_REASON_TRIPLE_FAULT:
            break;
    }
}