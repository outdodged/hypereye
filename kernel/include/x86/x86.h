#pragma once

#include <guest.h>

#include <linux/types.h>

// Exceptions
#define EXCEPTION_DE        0x0
#define EXCEPTION_DB        0x1
#define EXCEPTION_NMI       0x2
#define EXCEPTION_BP        0x3
#define EXCEPTION_OF        0x4
#define EXCEPTION_BR        0x5
#define EXCEPTION_UD        0x6
#define EXCEPTION_NM        0x7
#define EXCEPTION_DF        0x8
#define EXCEPTION_TS        0xa
#define EXCEPTION_NP        0xb
#define EXCEPTION_SS        0xc
#define EXCEPTION_GP        0xd
#define EXCEPTION_PF        0xe
#define EXCEPTION_MF        0x10
#define EXCEPTION_AC        0x11
#define EXCEPTION_MC        0x12
#define EXCEPTION_XF        0x13
#define EXCEPTION_HV        0x1c
#define EXCEPTION_VC        0x1d
#define EXCEPTION_SX        0x1e

// I/O ports
#define MAX_NUM_IO_PORTS    0x10000

extern void (*x86_io_port_handlers[MAX_NUM_IO_PORTS])(int, uint32_t, uint16_t, uint32_t*);

int x86_handle_io(int in, uint32_t op_size, uint16_t port, uint32_t *eax); // returns the result of eax

void x86_handle_mmio(internal_vcpu *vcpu, gpa_t phys_guest, int is_write);