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
#include <assert.h>
#include <elf.h>

#define TEST_IOCTL_RET(x) if (x) return EXIT_FAILURE;

int check_elf_magic(Elf32_Ehdr* hdr){
	return ((hdr->e_ident[EI_MAG0] == ELFMAG0) && (hdr->e_ident[EI_MAG1] == ELFMAG1) &&
			(hdr->e_ident[EI_MAG2] == ELFMAG2) && (hdr->e_ident[EI_MAG3] == ELFMAG3));
}

Elf32_Phdr* get_elf_program_header(Elf32_Ehdr* hdr, int index){
	return &(((Elf32_Phdr*)((long)hdr + hdr->e_phoff))[index]);
}

int main(int argc, char** argv) {
    FILE*                   fp;
	struct stat             st;
    Elf32_Ehdr*             ehdr;
    int						ctl_fd;
    uint64_t				guest_id;
    user_vcpu_guest_id		id_data;
    user_memory_region		region;
    user_arg_registers		regs;

    if (argc < 2) {
        printf("Need a kernel to load as second argument!\n");
        return EXIT_FAILURE;
    }

    ctl_fd = open(HYPEREYE_PROC_PATH, O_RDWR);
	if (ctl_fd == -1) {
		printf("Could not open " HYPEREYE_PROC_PATH "\n");
		return EXIT_FAILURE;
	}

    // Create a guest and a VCPU
	printf("Create guest\n");
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_CREATE_GUEST, &guest_id))
    id_data.guest_id = guest_id;
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_CREATE_VCPU, &id_data))

    // Read in the ELF file and load it into memory
    printf("Loading ELF\n");
	fp = fopen(argv[1], "r");
	if (fp == NULL){
		printf("\nError. ELF file not found: %s\n", argv[1]);
		return EXIT_FAILURE;
	}

    fstat(fileno(fp), &st);
	ehdr = (Elf32_Ehdr*) malloc(st.st_size);
	fseek(fp, 0L, SEEK_SET);
	fread(ehdr, sizeof(char), st.st_size, fp);

    printf("Check ELF header\n");
    if (!check_elf_magic(ehdr)){
		printf(" ELF Magic number is invalid.\n");
		return EXIT_FAILURE;
	}

    printf("Loading ELF into guest memory\n");
    // Copy all segments from the file into a memory region and map this into guest memory
	for (int i = 0; i < ehdr->e_phnum; i++){
		Elf32_Phdr* phdr = get_elf_program_header(ehdr, i);
		if (phdr->p_type == PT_LOAD){
            assert(phdr->p_memsz >= phdr->p_filesz);

            void* mem = mmap(NULL, phdr->p_memsz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            memcpy(mem, (void*)((uint64_t)(phdr->p_offset) + (uint64_t)(ehdr)), phdr->p_filesz);

            region.guest_id 		= guest_id;
            region.userspace_addr	= (uint64_t)mem;
            region.guest_addr		= phdr->p_vaddr;
            region.size				= phdr->p_memsz;
            region.is_mmio			= 0;
			region.is_cow			= 0;

            printf("Mapping file offset 0x%x to: 0x%x, len: 0x%x\n", phdr->p_offset, phdr->p_vaddr, phdr->p_memsz);

            TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_SET_MEMORY_REGION, &region))
		}
	}

    // Set the registers to their initial values
    memset(&regs, 0x0, sizeof(user_arg_registers));
    regs.guest_id = id_data.guest_id;
	regs.vcpu_id  = id_data.vcpu_id;
    TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_GET_REGISTERS, &regs))

    regs.rip = ehdr->e_entry;
	
    TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_SET_REGISTERS, &regs))

    // Now run the guest
    TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_VCPU_RUN, &id_data))

    printf("Get registers\n");
	TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_GET_REGISTERS, &regs))
	printf("Result rip: 0x%lx\n", regs.rip);
	printf("Result rax: 0x%lx\n", regs.rax);
	printf("Result rbx: 0x%lx\n", regs.rbx);
	printf("Result rcx: 0x%lx\n", regs.rcx);
	printf("Result rdx: 0x%lx\n", regs.rdx);
	printf("Result rdi: 0x%lx\n", regs.rdi);
	printf("Result rsi: 0x%lx\n", regs.rsi);
	printf("Result r9:  0x%lx\n", regs.r8);
	printf("Result r9:  0x%lx\n", regs.r9);
	printf("Result r10: 0x%lx\n", regs.r10);
	printf("Result r11: 0x%lx\n", regs.r11);
	printf("Result r12: 0x%lx\n", regs.r12);
	printf("Result r13: 0x%lx\n", regs.r13);
	printf("Result r14: 0x%lx\n", regs.r14);
	printf("Result r15: 0x%lx\n", regs.r15);
	printf("Result gdt selector: 0x%lx\n", regs.gdtr.selector);
	printf("Result gdt attrib: 0x%lx\n", regs.gdtr.attrib);
	printf("Result gdt limit: 0x%lx\n", regs.gdtr.limit);
	printf("Result gdt base: 0x%lx\n", regs.gdtr.base);
    // Cleanup
    TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_DESTROY_GUEST, &guest_id))
	close(ctl_fd);

    return EXIT_SUCCESS;
}