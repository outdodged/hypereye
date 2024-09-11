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
mov eax, [0x1000]
mov ebx, 1
mov [0x1000], ebx
mov ecx, [0x1000]
*/

#define TEST_CODE_SIZE	22
char* test_code = "\xa1\x00\x10\x00\x00\xbb\x01\x00\x00\x00\x89\x1d\x00\x10\x00\x00\x8b\x0d\x00\x10\x00\x00";

#define TEST_IOCTL_RET(x) if (x) return EXIT_FAILURE;

int main() {
	int						ctl_fd;
	void*					guest_page;
	user_arg_registers		regs;
	user_vcpu_guest_id		id_data;
	uint64_t				guest_id, vcpu_id;
	user_memory_region		region;
	
	ctl_fd = open(HYPEREYE_PROC_PATH, O_RDWR);
	if (ctl_fd == -1) {
		printf("Could not open " HYPEREYE_PROC_PATH "\n");
		return EXIT_FAILURE;
	}
	
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_CREATE_GUEST, &guest_id))
	id_data.guest_id = guest_id;
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_CREATE_VCPU, &id_data))

	guest_page = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (guest_page == MAP_FAILED) {
		printf("Could not allocate guest page\n");
		return EXIT_FAILURE;
	}
	memset(guest_page, 0xf4, 0x2000);
	memcpy(guest_page, test_code, TEST_CODE_SIZE);
	region.guest_id 		= guest_id;
	region.userspace_addr	= (uint64_t)guest_page;
	region.guest_addr		= 0;
	region.size				= 0x2000;
	region.is_mmio			= 0;
	region.is_cow			= 1;
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_SET_MEMORY_REGION, &region))
	
	id_data.guest_id = guest_id;
	id_data.vcpu_id  = vcpu_id;
	// First exit: lazy pagefault of code
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_VCPU_RUN, &id_data))
	// Second exit: lazy pagefault of data @ 0x1000
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_VCPU_RUN, &id_data))
	// Third exit: HLT instruction as last executed instruction
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_VCPU_RUN, &id_data))

	// Test the result
	regs.guest_id = guest_id;
	regs.vcpu_id  = vcpu_id;
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_GET_REGISTERS, &regs))
	printf("Result rax: 0x%lx\n", regs.rax);
	printf("Result rbx: 0x%lx\n", regs.rbx);
	printf("Result rcx: 0x%lx\n", regs.rcx);
    printf("Result [0x1000]: 0x%lx\n", *(unsigned long*)((unsigned long)guest_page + 0x1000));

	
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_DESTROY_GUEST, &guest_id))
	
	close(ctl_fd);
	
	return EXIT_SUCCESS;
}