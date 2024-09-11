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
mov eax, 0
mov ebx, 0x10
loop:
add eax, 1
cmp eax, ebx
jne loop
hlt
*/

#define TEST_CODE_SIZE	18
char* test_code = "\xb8\x00\x00\x00\x00\xbb\x10\x00\x00\x00\x83\xc0\x01\x39\xd8\x75\xf9\xf4";

#define TEST_IOCTL_RET(x) if (x) return EXIT_FAILURE;

int main() {
	int						ctl_fd;
	int						fuzz_fd;
	void*					guest_page;
	uint64_t*				breakpoints_map;
	uint64_t*				fuzz_mmap;
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

	fuzz_fd= open(HYPEREYE_FUZZ_PATH, O_RDWR);
	if (fuzz_fd == -1) {
		printf("Could not open " HYPEREYE_FUZZ_PATH "\n");
		return EXIT_FAILURE;
	}
	
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_CREATE_GUEST, &guest_id))
	id_data.guest_id = guest_id;
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_CREATE_VCPU, &id_data))

	guest_page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (guest_page == MAP_FAILED) {
		printf("Could not allocate guest page\n");
		return EXIT_FAILURE;
	}
	memset(guest_page, 0xf4, 0x1000);
	memcpy(guest_page, test_code, TEST_CODE_SIZE);
	region.guest_id 		= guest_id;
	region.userspace_addr	= (uint64_t)guest_page;
	region.guest_addr		= 0;
	region.size				= 0x1000;
	region.is_mmio			= 0;
	region.is_cow			= 1;
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_SET_MEMORY_REGION, &region))

	// Create breakpoints
	breakpoints_map = (uint64_t*) mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (breakpoints_map == MAP_FAILED) {
		printf("Could not allocate breakpoints_map page\n");
		return EXIT_FAILURE;
	}

	breakpoints_map[0] = 0x0;
	breakpoints_map[1] = 0xa;

	breakpoints.guest_id = id_data.guest_id;
	breakpoints.virt = 0;
	breakpoints.sz   = 0x16;
	breakpoints.addr = breakpoints_map;
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_SET_BREAKPOINTS, &breakpoints));

	// set the fuzzing counter region
	fuzz_mmap = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fuzz_fd, 0);
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_SET_FUZZ_CNTR_REGION, &guest_id));

	for (unsigned int i = 0; i < 0x1; i++) {
		TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_VCPU_RUN, &id_data))

		regs.guest_id = guest_id;
		regs.vcpu_id  = id_data.vcpu_id;
		TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_GET_REGISTERS, &regs))

		printf("rip: 0x%lx\n", regs.rip);
		printf("rax: 0x%lx\n", regs.rax);
		printf("rbx: 0x%lx\n", regs.rbx);
	}

	// Test the result
	regs.guest_id = guest_id;
	regs.vcpu_id  = id_data.vcpu_id;
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_GET_REGISTERS, &regs))

	printf("BP 0 times hit: 0x%x\n", fuzz_mmap[0]);
	printf("BP 1 times hit: 0x%x\n", fuzz_mmap[1]);
	
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_DESTROY_GUEST, &guest_id))
	
	close(ctl_fd);
	
	return EXIT_SUCCESS;
}