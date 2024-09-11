/*
 * This file contains basic definitions of datastructures and types used by AMD SVM.
 */

#pragma once

#include <linux/types.h>

// structure to represent x86 segment registers
struct __attribute__ ((__packed__)) segment {
	uint16_t	selector;
	uint16_t	attrib;
	uint32_t	limit;
	uint64_t	base;
} typedef segment;

// general VMCB structure (like in KVM)
struct __attribute__ ((__packed__)) internal_vmcb{
	// Control area
	uint32_t 	intercept_cr;
	uint32_t 	intercept_dr;
	uint32_t 	intercept_exceptions;
	uint64_t 	intercept; // various intercepts for different kinds of instructions
	uint8_t 	reserved_1[40];
	uint16_t	pause_filter_threshold;
	uint16_t	pause_filter_count;
	uint64_t	iopm_base_pa;
	uint64_t	msrprm_base_pa;
	uint64_t	tsc_offset;
	uint32_t	guest_asid;
	uint8_t		tlb_control;
	uint8_t		reserved_2[3];
	uint32_t	interrupt_control;
	uint32_t	interrupt_vector;
	uint32_t	interrupt_state;
	uint8_t		reserved_3[4];
	uint64_t	exitcode;
	uint64_t	exitinfo1;
	uint64_t	exitinfo2;
	uint64_t	exitintinfo;
	uint64_t	nested_and_sec_control;
	uint64_t	avic_apic_bar;
	uint64_t	ghcb_address;
	uint32_t 	event_inject;
	uint32_t 	event_inject_error;
	uint64_t 	n_cr3;
	uint64_t 	virt_ext;
	uint32_t 	vmcb_clean;
	uint8_t 	reserved_5[4];
	uint64_t 	next_rip;
	uint8_t 	insn_len;
	uint8_t 	insn_bytes[15];
	uint64_t 	avic_backing_page;
	uint8_t 	reserved_6[8];
	uint64_t	avic_logical_id;
	uint64_t 	avic_physical_id;
	uint8_t 	reserved_7[768];

	// Save area
	struct segment	es;
	struct segment	cs;
	struct segment	ss;
	struct segment	ds;
	struct segment	fs;
	struct segment	gs;
	struct segment	gdtr;
	struct segment	ldtr;
	struct segment	idtr;
	struct segment	tr;
	uint8_t 	reserved_8[43];
	uint8_t 	cpl;
	uint8_t		reserved_9[4];
	uint64_t	efer;
	uint8_t		reserved_10[112];
	uint64_t	cr4;
	uint64_t	cr3;
	uint64_t	cr0;
	uint64_t	dr7;
	uint64_t	dr6;
	uint64_t	rflags;
	uint64_t	rip;
	uint8_t		reserved_11[88];
	uint64_t	rsp;
	uint8_t		reserved_12[24];
	uint64_t	rax;
	uint64_t	star;
	uint64_t	lstar;
	uint64_t	cstar;
	uint64_t	sfmask;
	uint64_t	kernel_gs_base;
	uint64_t	sysenter_cs;
	uint64_t	sysenter_esp;
	uint64_t	sysenter_eip;
	uint64_t	cr2;
	uint8_t		reserved_13[32];
	uint64_t	gpat;
	uint64_t	dbgctl;
	uint64_t	br_from;
	uint64_t	br_to;
	uint64_t	last_excp_from;
	uint64_t	last_excp_to;
} typedef internal_vmcb;
_Static_assert (sizeof(internal_vmcb) == 0x698, "vmcb struct size false");

// a struct representing the guest general purpose register state: these
// will not be stored in the VMCB
struct __attribute__ ((__packed__)) svm_gp_regs {
	uint64_t 	rbx;
	uint64_t 	rcx;
	uint64_t 	rdx;
	uint64_t 	rdi;
	uint64_t 	rsi;
	uint64_t 	r8;
	uint64_t 	r9;
	uint64_t 	r10;
	uint64_t 	r11;
	uint64_t 	r12;
	uint64_t 	r13;
	uint64_t 	r14;
	uint64_t 	r15;
	uint64_t 	rbp;
	uint64_t	xmm0 [2];
	uint64_t	xmm1 [2];
	uint64_t	xmm2 [2];
	uint64_t	xmm3 [2];
	uint64_t	xmm4 [2];
	uint64_t	xmm5 [2];
	uint64_t	xmm6 [2];
	uint64_t	xmm7 [2];
	uint64_t	xmm8 [2];
	uint64_t	xmm9 [2];
	uint64_t	xmm10[2];
	uint64_t	xmm11[2];
	uint64_t	xmm12[2];
	uint64_t	xmm13[2];
	uint64_t	xmm14[2];
	uint64_t	xmm15[2];
} typedef svm_gp_regs;

// Intercept related
/*
#define INTERCEPT_MSR_PROT		((28 + 32) << 1)
#define INTERCEPT_HLT			((uint64_t)1 << 24)
#define INTERCEPT_VMRUN			((uint64_t)1 << 32)*/

// MSR intercept
#define MSRPM_SIZE			0x1000 * 4

// Intercept exit codes
#define VMEXIT_READ_CR0      	0x00
#define VMEXIT_READ_CR2      	0x02
#define VMEXIT_READ_CR3      	0x03
#define VMEXIT_READ_CR4      	0x04
#define VMEXIT_READ_CR8      	0x08
#define VMEXIT_WRITE_CR0     	0x10
#define VMEXIT_WRITE_CR2     	0x12
#define VMEXIT_WRITE_CR3     	0x13
#define VMEXIT_WRITE_CR4     	0x14
#define VMEXIT_WRITE_CR8     	0x18
#define VMEXIT_READ_DR0      	0x20
#define VMEXIT_READ_DR1      	0x21
#define VMEXIT_READ_DR2      	0x22
#define VMEXIT_READ_DR3      	0x23
#define VMEXIT_READ_DR4      	0x24
#define VMEXIT_READ_DR5      	0x25
#define VMEXIT_READ_DR6      	0x26
#define VMEXIT_READ_DR7      	0x27
#define VMEXIT_WRITE_DR0     	0x30
#define VMEXIT_WRITE_DR1     	0x31
#define VMEXIT_WRITE_DR2     	0x32
#define VMEXIT_WRITE_DR3     	0x33
#define VMEXIT_WRITE_DR4     	0x34
#define VMEXIT_WRITE_DR5     	0x35
#define VMEXIT_WRITE_DR6     	0x36
#define VMEXIT_WRITE_DR7     	0x37
#define VMEXIT_EXCP_BASE     	0x40
#define VMEXIT_INTR          	0x60
#define VMEXIT_NMI           	0x61
#define VMEXIT_SMI           	0x62
#define VMEXIT_INIT          	0x63
#define VMEXIT_VINTR         	0x64
#define VMEXIT_CR0_SEL_WRITE 	0x65
#define VMEXIT_IDTR_READ     	0x66
#define VMEXIT_GDTR_READ     	0x67
#define VMEXIT_LDTR_READ     	0x68
#define VMEXIT_TR_READ       	0x69
#define VMEXIT_IDTR_WRITE    	0x6A
#define VMEXIT_GDTR_WRITE    	0x6B
#define VMEXIT_LDTR_WRITE    	0x6E
#define VMEXIT_TR_WRITE      	0x6D
#define VMEXIT_RDTSC			0x6E
#define VMEXIT_RDPMC			0x6F
#define VMEXIT_PUSHF			0x70
#define VMEXIT_CPUID			0x72
#define VMEXIT_RSM				0x73
#define VMEXIT_IRET				0x74
#define VMEXIT_INVD				0x76
#define VMEXIT_PAUSE			0x77
#define VMEXIT_HLT				0x78
#define VMEXIT_INVLPG			0x79
#define VMEXIT_INVLPGA			0x7a
#define VMEXIT_IOIO				0x7b
#define VMEXIT_MSR 				0x7c
#define VMEXIT_SHUTDOWN			0x7f
#define VMEXIT_VMRUN 			0x80
#define VMEXIT_VMMCALL			0x81
#define VMEXIT_VMLOAD			0x82
#define VMEXIT_VMSAVE			0x83
#define VMEXIT_STGI				0x84
#define VMEXIT_CLGI				0x85
#define VMEXIT_SKINIT			0x86
#define VMEXIT_RDTSCP			0x87
#define VMEXIT_ICEBP			0x88
#define VMEXIT_MONITOR			0x8A
#define VMEXIT_MWAIT			0x8B
#define VMEXIT_RDPRU			0x8E
#define VMEXIT_MWAIT_COND    	0x8C
#define VMEXIT_XSETBV			0x8D
#define VMEXIT_RDPRU         	0x8E
#define VMEXIT_INVLPGB			0xA0
#define VMEXIT_MCOMMIT			0xA3
#define VMEXIT_TLBSYNC			0xA4
#define VMEXIT_NPF				0x400
#define VMEXIT_INVALID			0xffffffffffffffff

// NPF exitcodes
#define NPF_NOT_PRESENT			((uint64_t)1 << 0)
#define NPF_WRITE_ACCESS		((uint64_t)1 << 1)
#define NPF_USER_ACCESS			((uint64_t)1 << 2)
#define NPF_RESERVED			((uint64_t)1 << 3)
#define NPF_CODE_ACCESS			((uint64_t)1 << 4)
#define NPF_IN_VMM_PAGE			((uint64_t)1 << 32)
#define NPF_IN_GUEST_PAGE		((uint64_t)1 << 33)

// TLB flushing
#define TLB_FLUSH_NONE			((uint8_t)0)
#define TLB_FLUSH_ALL			((uint8_t)0x1)
#define TLB_FLUSH_THIS			((uint8_t)0x3)
#define TLB_FLUSH_NON_GLOBAL	((uint8_t)0x7)

// Event injection
#define EVENT_INJECT_ERROR_VALID		((uint64_t)1 << 11)
#define EVENT_INJECT_VALID				((uint64_t)1 << 31)
#define EVENT_INJECT_TYPE_INTR			((uint64_t)0)
#define EVENT_INJECT_TYPE_NMI			((uint64_t)2)
#define EVENT_INJECT_TYPE_EXCEPTION		((uint64_t)3)
#define EVENT_INJECT_TYPE_INTN			((uint64_t)4)

// VMCB cache dirty bits
#define VMCB_DIRTY_I					((uint32_t)1 << 0)
#define VMCB_DIRTY_IOPM					((uint32_t)1 << 1)
#define VMCB_DIRTY_ASID					((uint32_t)1 << 2)
#define VMCB_DIRTY_TPR					((uint32_t)1 << 3)
#define VMCB_DIRTY_NP					((uint32_t)1 << 4)
#define VMCB_DIRTY_CRX					((uint32_t)1 << 5)
#define VMCB_DIRTY_DRX					((uint32_t)1 << 6)
#define VMCB_DIRTY_DT					((uint32_t)1 << 7)
#define VMCB_DIRTY_SEG					((uint32_t)1 << 8)
#define VMCB_DIRTY_CR2					((uint32_t)1 << 9)
#define VMCB_DIRTY_LBR					((uint32_t)1 << 10)
#define VMCB_DIRTY_AVIC					((uint32_t)1 << 11)
#define VMCB_DIRTY_ALL_CLEAN			((uint32_t)0xffffffff)
#define VMCB_DIRTY_ALL_DIRTY			((uint32_t)0x0)