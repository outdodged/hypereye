#include <svm/svm.h>

#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kprobes.h>
#include <linux/kvm_host.h>
#include <asm/svm.h>

#define MAX_NUM_IO_PORTS                0x10000
#define MAX_TRACKED_IO_PORTS            0x20
#define MAX_TRACKED_REPLIES_PER_PORT    0x1000

#define VMEXIT_IOIO				        0x7b

internal_guest      kvm_guest;
struct kvm_vcpu*    observed_kvm_vcpus[MAX_NUM_VCPUS]; // upon every svm_vcpu_run() call, record the executed VCPUs here

unsigned int        io_port_counter[MAX_NUM_IO_PORTS];
uint32_t            io_record_array[MAX_TRACKED_IO_PORTS][MAX_TRACKED_REPLIES_PER_PORT]; // first entry is always the port number
uint32_t            io_record_cntr[MAX_TRACKED_IO_PORTS];

struct              vmcb* kvm_vmcb = NULL;
struct              kvm_vcpu *kvm_vcpu = NULL;
struct              vcpu_svm* kvm_svm = NULL;
static struct       kretprobe probe_svm_vcpu_run;

struct vcpu_svm {
	struct kvm_vcpu vcpu;
	struct vmcb *vmcb;
    // the rest here is cut of since we don't need to duplicate all the code
};

static inline struct vcpu_svm *to_svm(struct kvm_vcpu *vcpu) { return container_of(vcpu, struct vcpu_svm, vcpu); }

static int entry_hook_svm_vcpu_run(struct kretprobe_instance *ri, struct pt_regs *regs) {
    uint16_t					port;
    unsigned int                i;
    unsigned int                in;
    int                         found;

    kvm_vcpu = (struct kvm_vcpu*)(regs->di);
    kvm_svm = to_svm(kvm_vcpu);

    kvm_vmcb = kvm_svm->vmcb;

    // Record the observed KVM VCPU
    found = 0;
    for (i = 0; i < MAX_NUM_VCPUS; i++) {
        if (observed_kvm_vcpus[i] == kvm_vcpu) found = 1;
    }
    if (found == 0) {
        for (i = 0; i < MAX_NUM_VCPUS; i++) {
            if (observed_kvm_vcpus[i] == NULL) observed_kvm_vcpus[i] = kvm_vcpu;
        }
    }

    // Count up the IO counter
    // Why before the "next" run and not at return of svm_vcpu_run()? Because IO emulation
    // can take place in userland.
    if (kvm_vmcb->control.exit_code == VMEXIT_IOIO) {
        port 	= (uint16_t)(kvm_vmcb->control.exit_info_1 >> 16);
        in 		= (kvm_vmcb->control.exit_info_1 & (1 << 0)) ? 1 : 0;
        io_port_counter[port]++;

        if (in) {
            // Record the eax value
            for (i = 0; i < MAX_TRACKED_IO_PORTS; i++) {
                if (io_record_array[i][0] == port) {
                    io_record_array[i][io_record_cntr[i]] = kvm_vmcb->save.rax;
                    io_record_cntr[i]++;
                }
            }

            // If we didn't find an entry in the array, we have to create
            // a new one for the port
            for (i = 0; i < MAX_TRACKED_IO_PORTS; i++) {
                if (io_record_array[i][0] == 0) {
                    io_record_array[i][0] = port;
                    io_record_array[i][io_record_cntr[i]] = kvm_vmcb->save.rax;
                    io_record_cntr[i]++;
                }
            }
        }
    }

    return 0;
}

static int ret_hook_svm_vcpu_run(struct kretprobe_instance *ri, struct pt_regs *regs) {
	return 0;
}

void svm_register_kvm_record_handler(void) {
    unsigned int i;

    printk(DBG "Registering KVM recorder");

    memset(&io_port_counter[0], 0, MAX_NUM_IO_PORTS * sizeof(unsigned int));
    for (i = 0; i < MAX_TRACKED_IO_PORTS; i++) {
        io_record_array[i][0] = 0;
    }
    
    probe_svm_vcpu_run.kp.symbol_name = "svm_vcpu_run";
    probe_svm_vcpu_run.handler = ret_hook_svm_vcpu_run;
    probe_svm_vcpu_run.entry_handler = entry_hook_svm_vcpu_run;

    if (register_kretprobe(&probe_svm_vcpu_run) < 0) {
        printk(DBG "Error registering kretprobe for svm_vcpu_run()\n");
    }
}

void svm_deregister_kvm_record_handler(void) {
    unsigned int    i;
    internal_vcpu   *vcpu;
    svm_internal_vcpu	*svm_vcpu;

    printk(DBG "Deregistering KVM recorder");

    unregister_kretprobe(&probe_svm_vcpu_run);

    for (i = 0; i < MAX_NUM_IO_PORTS; i++) {
        if (io_port_counter[i] != 0) {
            printk(DBG "port: 0x%x, cnt: 0x%x\n", i, io_port_counter[i]);
        }
    }

    // Init the kvm_guest structure with all observed KVM VCPUS.
    for (i = 0; i < MAX_NUM_VCPUS; i++) {
        if (observed_kvm_vcpus[i] != NULL) {
            vcpu = create_vcpu(&kvm_guest);
            if (vcpu != NULL) {
                // Copy the content of the KVM VMCBs into the HYPEREYE VMCBs of
                // a selected  guest.
                kvm_svm = to_svm(observed_kvm_vcpus[i]);
                kvm_vmcb = kvm_svm->vmcb;

                svm_vcpu = to_svm_vcpu(vcpu);

                memcpy(svm_vcpu->vcpu_vmcb, kvm_vmcb, sizeof(internal_vmcb));

                // Also copy the contents of the remaining registers into our VCPU
                svm_vcpu->vcpu_regs->rbx = observed_kvm_vcpus[i]->arch.regs[VCPU_REGS_RBX];
                svm_vcpu->vcpu_regs->rcx = observed_kvm_vcpus[i]->arch.regs[VCPU_REGS_RCX];
                svm_vcpu->vcpu_regs->rdx = observed_kvm_vcpus[i]->arch.regs[VCPU_REGS_RDX];
                svm_vcpu->vcpu_regs->rdi = observed_kvm_vcpus[i]->arch.regs[VCPU_REGS_RDI];
                svm_vcpu->vcpu_regs->rsi = observed_kvm_vcpus[i]->arch.regs[VCPU_REGS_RSI];
                svm_vcpu->vcpu_regs->r8  = observed_kvm_vcpus[i]->arch.regs[VCPU_REGS_R8];
                svm_vcpu->vcpu_regs->r9  = observed_kvm_vcpus[i]->arch.regs[VCPU_REGS_R9];
                svm_vcpu->vcpu_regs->r10 = observed_kvm_vcpus[i]->arch.regs[VCPU_REGS_R10];
                svm_vcpu->vcpu_regs->r11 = observed_kvm_vcpus[i]->arch.regs[VCPU_REGS_R11];
                svm_vcpu->vcpu_regs->r12 = observed_kvm_vcpus[i]->arch.regs[VCPU_REGS_R12];
                svm_vcpu->vcpu_regs->r13 = observed_kvm_vcpus[i]->arch.regs[VCPU_REGS_R13];
                svm_vcpu->vcpu_regs->r14 = observed_kvm_vcpus[i]->arch.regs[VCPU_REGS_R14];
                svm_vcpu->vcpu_regs->r15 = observed_kvm_vcpus[i]->arch.regs[VCPU_REGS_R15];
                svm_vcpu->vcpu_regs->rbp = observed_kvm_vcpus[i]->arch.regs[VCPU_REGS_RBP];

                // Copy arch-internal guest parameters into kvm_guest
                
            } else {
                destroy_vcpu(vcpu);
            }
        }
    }
}