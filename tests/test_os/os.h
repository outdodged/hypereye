#pragma once

#include <stdint.h>

#define PAGE_TABLE_MASK          (uint64_t)0x7FFFFFFFFFFFF000 // Also mask out NX bit (bit 63)

#define PAGE_ATTRIB_PRESENT     ((uint64_t)1 << 0)
#define PAGE_ATTRIB_WRITE       ((uint64_t)1 << 1)

struct __attribute__ ((__packed__)) segment_descriptor {
	uint16_t	limit_1;
	uint16_t	base_addr_1;
	uint8_t	    base_addr_2;
    uint16_t	attrib;
    uint8_t	    base_addr_3;
} typedef segment_descriptor;

struct __attribute__ ((__packed__)) descriptor_ptr {
	uint16_t	limit;
	uint32_t	addr;
} typedef descriptor_ptr;

extern descriptor_ptr gdt_ptr;

// 32-Bit code for pagetable setup
void* create_mapping_32(void);