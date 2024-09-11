#include "os.h"

segment_descriptor gdt[] = {
    // Null descriptor
    {
        .limit_1        = 0,
        .base_addr_1    = 0,
        .base_addr_2    = 0,
        .attrib         = 0,
        .base_addr_3    = 0
    },
    // Code segment: TODO
    {
        .limit_1        = 0,
        .base_addr_1    = 0,
        .base_addr_2    = 0,
        .attrib         = 0,
        .base_addr_3    = 0
    },
    // Data segment
    {
        .limit_1        = 0,
        .base_addr_1    = 0,
        .base_addr_2    = 0,
        .attrib         = 0x8000,
        .base_addr_3    = 0
    }
};

descriptor_ptr gdt_ptr;

struct __attribute__ ((__packed__)) idt_descriptor {
   uint16_t     base_addr_1;
   uint16_t     selector;
   uint8_t      ist;
   uint8_t      attrib;
   uint16_t     base_addr_2;
   uint32_t     base_addr_3;
   uint32_t     zero;
} typedef idt_descriptor;

idt_descriptor idt[256];

void add_idt_descriptor(uint8_t vector, void* handler, uint16_t selector, uint8_t ist, uint8_t attrib) {
    idt[vector].base_addr_1 = ((uint64_t)handler) | 0xffff;
    idt[vector].base_addr_2 = (((uint64_t)handler) >> 16) | 0xffff;
    idt[vector].base_addr_3 = (((uint64_t)handler) >> 32) | 0xffffffff;

    idt[vector].selector    = selector;
    idt[vector].ist         = ist;
    idt[vector].attrib      = attrib;
}

void kmain() {
    // Load and set up the IDT
    // TODO
    add_idt_descriptor(0, 0, 0, 0, 0);
}