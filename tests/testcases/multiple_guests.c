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

/*
Assembly:
label1:
jmp label1
*/

#define TEST_CODE_SIZE	1
char* test_code = "\xf4";

#define TEST_IOCTL_RET(x) if (x) return EXIT_FAILURE;

int main() {
	int						ctl_fd;
	void*					guest_page;
	user_arg_registers		regs;
	user_vcpu_guest_id		id_data_1;
    user_vcpu_guest_id		id_data_2;
	uint64_t				guest_id_1 = GUEST_CREATE_NEW;
    uint64_t                vcpu_id_1;
    uint64_t				guest_id_2 = GUEST_CREATE_NEW;
    uint64_t                vcpu_id_2;
	user_memory_region		region;
	
	ctl_fd = open(HYPEREYE_PROC_PATH, O_RDWR);
	if (ctl_fd == -1) {
		printf("Could not open " HYPEREYE_PROC_PATH "\n");
		return EXIT_FAILURE;
	}

    // Create two guests with VCPUs
	printf("Create guest 1\n");
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_CREATE_GUEST, &guest_id_1))
	id_data_1.guest_id = guest_id_1;
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_CREATE_VCPU, &id_data_1))

	printf("Create guest 2\n");
	//printf("&guest_id_2: 0x%lx\n", &guest_id_2);
	//printf("&id_data_2: 0x%lx\n", &id_data_2);
    TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_CREATE_GUEST, &guest_id_2))
	id_data_2.guest_id = guest_id_2;
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_CREATE_VCPU, &id_data_2))

	guest_page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (guest_page == MAP_FAILED) {
		printf("Could not allocate guest page\n");
		return EXIT_FAILURE;
	}
	memset(guest_page, 0xf4, 0x1000);
	memcpy(guest_page, test_code, TEST_CODE_SIZE);
	region.userspace_addr	= (uint64_t)guest_page;
	region.guest_addr		= 0;
	region.size				= 0x1000;
	region.is_mmio			= 0;
	region.is_cow			= 1;

    region.guest_id 		= guest_id_1;
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_SET_MEMORY_REGION, &region))
    region.guest_id 		= guest_id_2;
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_SET_MEMORY_REGION, &region))
	
    printf("Run guest 1\n");
	id_data_1.guest_id = guest_id_1;
	id_data_1.vcpu_id  = vcpu_id_1;
	// First exit: lazy pagefault of code
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_VCPU_RUN, &id_data_1))
	// Second exit: lazy pagefault of data @ 0x1000
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_VCPU_RUN, &id_data_1))
	// Third exit: HLT instruction as last executed instruction
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_VCPU_RUN, &id_data_1))
    
    printf("Destroy guest 1\n");
    TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_DESTROY_GUEST, &guest_id_1))

    printf("Run guest 2\n");
    id_data_2.guest_id = guest_id_2;
	id_data_2.vcpu_id  = vcpu_id_2;
	// First exit: lazy pagefault of code
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_VCPU_RUN, &id_data_2))
	// Second exit: lazy pagefault of data @ 0x1000
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_VCPU_RUN, &id_data_2))
	// Third exit: HLT instruction as last executed instruction
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_VCPU_RUN, &id_data_2))
	
    printf("Destroy guest 2\n");
    TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_DESTROY_GUEST, &guest_id_2))

    printf("Run guest 2\n");
    TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_VCPU_RUN, &id_data_2))

    printf("Done\n");

	close(ctl_fd);
	
	return EXIT_SUCCESS;
}