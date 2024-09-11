#include <stdint.h>
#include <HYPEREYE_defs.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

// Expects a QEMU VM image named "ubuntu.qcow2" in the repository root

#define TEST_IOCTL_RET(x) if (x) return EXIT_FAILURE;

int main() {
	int						ctl_fd;
	void*					guest_page;
	uint64_t*				breakpoints_map;
	user_arg_registers		regs;
	user_vcpu_guest_id		id_data;
	uint64_t				guest_id;
	user_memory_region		region;
	user_breakpoints		breakpoints;
	
	ctl_fd = open(HYPEREYE_PROC_PATH, O_RDWR);
	if (ctl_fd == -1) {
		printf("Could not open " HYPEREYE_PROC_PATH "\n");
		return EXIT_FAILURE;
	}

    // Start the QEMU VM
    if (system("qemu-system-x86_64 -hda ../../ubuntu.qcow2  -m 4G -monitor telnet:127.0.0.1:1234,server,nowait -accel kvm &") != EXIT_SUCCESS) {
        printf("socat failed! Maybe another program is connected to the monitor?");
        return EXIT_FAILURE;
    }

	// while installing the KVM function hooks, stop execution of the 
    // QEMU instance
    if (system("echo \"stop\" | socat - unix-connect:$(pwd)/../../monitor") != EXIT_SUCCESS) {
        printf("socat failed! Maybe another program is connected to the monitor?");
        return EXIT_FAILURE;
    }

    // Enable HYPEREYE KVM tracing
    TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_BEGIN_KVM_RECORD, NULL))

    sleep(10);

    // Continue execution of the QEMU VM in order to trace it
    if (system("echo \"cont\" | socat - unix-connect:$(pwd)/../../monitor") != EXIT_SUCCESS) {
        printf("socat failed! Maybe another program is connected to the monitor?");
        return EXIT_FAILURE;
    }

    // Now create a HYPEREYE guest from the recorded trace
    guest_id = GUEST_CREATE_KVM_REC;
    TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_CREATE_GUEST, &guest_id))
	id_data.guest_id = guest_id;
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_CREATE_VCPU, &id_data))

	for (unsigned int i = 0; i < 0x1; i++) {
		TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_VCPU_RUN, &id_data))

		regs.guest_id = guest_id;
		regs.vcpu_id  = id_data.vcpu_id;
		TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_GET_REGISTERS, &regs))
	}

	// Test the result
	regs.guest_id = guest_id;
	regs.vcpu_id  = id_data.vcpu_id;
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_GET_REGISTERS, &regs))
	
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_DESTROY_GUEST, &guest_id))
	
	close(ctl_fd);
	
	return EXIT_SUCCESS;
}