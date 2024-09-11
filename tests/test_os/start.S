.intel_syntax noprefix

.section .bss
	.align 16
sp_bottom:
	.skip 8192
sp_top:

.section .data
gdt64:
	gdt64nullseg:	.quad 0x0			# Null descriptor
	gdt64codeseg:	.quad 0x00209A00000000000	#code segment descriptor
	gdb64dataseg:	.quad 0x00008000000000000	# data segment descriptor

gdt64ptr:
	gdt64limit:	.word . - gdt64 - 1
	gdb64addr:	.int gdt64

.section .text
.code32
.global _start
.type _start, @function
_start:
	cli

	# create a first stack for our C environment
 	lea esp, sp_top
	sub esp, 4

_enter_longmode:
	# steps to do in order to switch to long mode:
	# 1) disable paging
	# 2) set CR3 for paging
	# 3) enable PAE
	# 4) enterlong mode
	# 5) enable paging
	
	# disable paging: clear bit 31 of cr0
	mov eax, cr0
	and eax, 0x7FFFFFFF
	mov cr0, eax
	#mov eax, 0x2008
	#mov dword ptr[eax], 0x90
	
	# setup initial identity paging
	call create_mapping_32
	mov cr3, eax

	# enable PAE
	mov eax, cr4
	or eax, 0b10000		# bit 5 : PAE
	mov cr4, eax

	# make the final switch to long mode
	mov ecx, 0xC0000080	# get the EFER MSR
	rdmsr
	or ecx, 0b10000000	# bit 8: LM, enable long mode
	wrmsr

	# enable paging
	mov eax, cr0
	or eax, 1 << 31		# bit 31: PG, paging bit
	or eax, 1 << 4		# bit 4: ET, extension type
	or eax, 1 << 0		# bit 0: PE, protection mode enable
	mov cr0, eax

	# load the GDT for long mode
	lgdt [gdt64ptr]
	
	# jump to 64 bit code
	jmp 0x8:_64bits

.code64
_64bits:
	# 0x10: offset of the data segment descriptor
	mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

_enter_kernel:

	call kmain
	cli
_loop:
	hlt
	jmp _loop

.size _start, .-_start

# return to AT&T syntax for the compiler generated code
.att_syntax noprefix
