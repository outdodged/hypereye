/*
 Fuzzing of ioctls using a single guest.
*/

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
#include <time.h>

#define MAX_MMAP_REGIONS            128

void* mmap_regions[MAX_MMAP_REGIONS];
size_t  mmap_sizes[MAX_MMAP_REGIONS];
unsigned int mmap_regions_counter = 0; 

int main(int argc, char** argv) {
    int						ctl_fd;
    user_arg_registers		regs;
	user_vcpu_guest_id		id_data;
	uint64_t				guest_id;
	user_memory_region		region;
    unsigned int            r;

    srand(time(0));

    ctl_fd = open(HYPEREYE_PROC_PATH, O_RDWR);
    if (ctl_fd == -1) {
		printf("Could not open " HYPEREYE_PROC_PATH "\n");
		return EXIT_FAILURE;
	}

    // Fuzz for as long as possible.
    while (1) {
        ioctl(ctl_fd, HYPEREYE_IOCTL_CREATE_GUEST, &guest_id);

        for (unsigned int i = 0; i < rand() % 256; i++) {
            unsigned int cmd = rand() % 5 + 1;

            switch (cmd) {
                case 1 :
                    id_data.guest_id = guest_id;
                    ioctl(ctl_fd, HYPEREYE_IOCTL_CREATE_VCPU, &id_data); 
                    break;
                case 2:
                case 3: 
                    memset(&regs, rand(), sizeof(user_arg_registers));
                    regs.guest_id = guest_id;
                    regs.vcpu_id  = rand() % 2 == 0 ? rand() % 20: id_data.vcpu_id;
                    ioctl(ctl_fd, HYPEREYE_IOCTL_SET_REGISTERS, &regs);
                    break;
                case 4 : 
                    id_data.guest_id = guest_id;
                    id_data.vcpu_id = rand() % 20;
                    ioctl(ctl_fd, HYPEREYE_IOCTL_VCPU_RUN, &id_data);
                    break;
                case 5 :
                    // skip guest destruction command 
                    break;
                case 6 :
                    r = rand() % 3;

                    if (r == 0) {
                        unsigned int idx = rand() % (MAX_MMAP_REGIONS - 1);
                        size_t sz = rand() % 0x10000;

                        mmap_regions[idx] = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                        mmap_sizes[idx] = sz;
                        region.guest_id 		= guest_id;
                        region.userspace_addr	= (uint64_t)mmap_regions[idx];
                        region.guest_addr		= rand();
                        region.size				= rand() % 0x20000;
                        region.is_mmio			= 0;
                        region.is_cow			= rand() % 2;
                        ioctl(ctl_fd, HYPEREYE_SET_MEMORY_REGION, &region);
                    }
                    if (r == 1) {
                        for (unsigned int j = 0; j < rand() % (MAX_MMAP_REGIONS - 1); j++) {
                            unsigned int idx = rand() % (MAX_MMAP_REGIONS - 1);
                            
                            munmap(mmap_regions[idx], mmap_sizes[idx]);
                        }
                    }
                    if (r == 2) {
                        unsigned int idx = rand() % (MAX_MMAP_REGIONS - 1);

                        region.guest_id 		= guest_id;
                        region.userspace_addr	= (uint64_t)mmap_regions[idx];
                        region.guest_addr		= rand();
                        region.size				= rand() % 0x20000;
                        region.is_mmio			= 0;
                        region.is_cow			= rand() % 2;
                        ioctl(ctl_fd, HYPEREYE_SET_MEMORY_REGION, &region);
                    }
                    break;
            }
        }

        ioctl(ctl_fd, HYPEREYE_IOCTL_DESTROY_GUEST, &guest_id);
    }

    // Will never be reached.
    close(ctl_fd);
    return EXIT_SUCCESS;
}