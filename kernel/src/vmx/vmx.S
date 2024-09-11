    .text
LC0:
.globl vmx_vmptrst
vmx_vmptrst:
    vmptrst %rdi
    ret

.globl vmx_vmptrld
vmx_vmptrld:
    vmptrld %rdi
    ret

.globl vmx_vmclear
vmx_vmclear:
    vmclear %rdi
    ret

.globl vmx_vmresume
vmx_vmresume:
    vmresume  %rdi
    ret

.gobl vmx_vmlaunch
vmx_vmlaunch:
    vmlaunch  %rdi
    ret

.globl vmx_vmxon
vmx_vmxon:
    ret

.globl vmx_vmread
vmx_vmread:
    vmread %rax, %rdi
    ret

.globl vmx_vmwrite
vmx_vmwrite:
    vmwrite %rdi, %rsi
    ret

// Called if the vCPU exits and execution is returned to the hypervisor
.global vmx_vm_exit:
vmx_vm_exit:
    // Copy the guest registers to the VCPU struct
    movq	%rbx,     0(%rsp)
    movq	%rcx,     8(%rsp)
    movq	%rdx,    16(%rsp)
    movq	%rdi,    24(%rsp)
    movq	%rsi,    32(%rsp)
    movq	%r8,     40(%rsp)
    movq	%r9,     48(%rsp)
    movq	%r10,    56(%rsp)
    movq	%r11,    64(%rsp)
    movq	%r12,    72(%rsp)
    movq	%r13,    80(%rsp)
    movq	%r14,    88(%rsp)
    movq	%r15,    96(%rsp)
    movq	%rbp,   104(%rsp)
    movdqu	%xmm0,  112(%rsp)
    movdqu	%xmm1,  128(%rsp)
    movdqu	%xmm2,  144(%rsp)
    movdqu	%xmm3,  160(%rsp)
    movdqu	%xmm4,  176(%rsp)
    movdqu	%xmm5,  192(%rsp)
    movdqu	%xmm6,  208(%rsp)
    movdqu	%xmm7,  224(%rsp)
    movdqu	%xmm8,  240(%rsp)
    movdqu	%xmm9,  256(%rsp)
    movdqu	%xmm10, 272(%rsp)
    movdqu	%xmm11, 288(%rsp)
    movdqu	%xmm12, 304(%rsp)
    movdqu	%xmm13, 320(%rsp)
    movdqu	%xmm14, 336(%rsp)
    movdqu	%xmm15, 352(%rsp)

    call vmx_handle_vm_exit

// Runs a vCPU
.globl vmx_run_vcpu_asm_vmlaunch
vmx_run_vcpu_asm_vmlaunch:
    // Store the vmcs pointer on the stack
    pushq %rdi
    // Load the guest register state
    movq       0  (%rsp), %rbx 
    movq       8  (%rsp), %rcx
    movq       16 (%rsp), %rdx
    movq       24 (%rsp), %rdi
    movq       32 (%rsp), %rsi
    movq       40 (%rsp), %r8
    movq       48 (%rsp), %r9
    movq       56 (%rsp), %r10
    movq       64 (%rsp), %r11
    movq       72 (%rsp), %r12
    movq       80 (%rsp), %r13
    movq       88 (%rsp), %r14
    movq       96 (%rsp), %r15
    movq       104(%rsp), %rbp
    movdqu     112(%rsp), %xmm0
    movdqu     128(%rsp), %xmm1
    movdqu     144(%rsp), %xmm2
    movdqu     160(%rsp), %xmm3
    movdqu     176(%rsp), %xmm4
    movdqu     192(%rsp), %xmm5
    movdqu     208(%rsp), %xmm6
    movdqu     224(%rsp), %xmm7
    movdqu     240(%rsp), %xmm8
    movdqu     256(%rsp), %xmm9
    movdqu     272(%rsp), %xmm10
    movdqu     288(%rsp), %xmm11
    movdqu     304(%rsp), %xmm12
    movdqu     320(%rsp), %xmm13
    movdqu     336(%rsp), %xmm14
    movdqu     352(%rsp), %xmm15
    vmlaunch   0  (%rsp)
    ret

// Resumes a vCPU
.globl vmx_run_vcpu_asm_vmresume
vmx_run_vcpu_asm_vmresume:
    // Store the vmcs pointer on the stack
    pushq %rdi
    // Load the guest register state
    movq       0  (%rsp), %rbx 
    movq       8  (%rsp), %rcx
    movq       16 (%rsp), %rdx
    movq       24 (%rsp), %rdi
    movq       32 (%rsp), %rsi
    movq       40 (%rsp), %r8
    movq       48 (%rsp), %r9
    movq       56 (%rsp), %r10
    movq       64 (%rsp), %r11
    movq       72 (%rsp), %r12
    movq       80 (%rsp), %r13
    movq       88 (%rsp), %r14
    movq       96 (%rsp), %r15
    movq       104(%rsp), %rbp
    movdqu     112(%rsp), %xmm0
    movdqu     128(%rsp), %xmm1
    movdqu     144(%rsp), %xmm2
    movdqu     160(%rsp), %xmm3
    movdqu     176(%rsp), %xmm4
    movdqu     192(%rsp), %xmm5
    movdqu     208(%rsp), %xmm6
    movdqu     224(%rsp), %xmm7
    movdqu     240(%rsp), %xmm8
    movdqu     256(%rsp), %xmm9
    movdqu     272(%rsp), %xmm10
    movdqu     288(%rsp), %xmm11
    movdqu     304(%rsp), %xmm12
    movdqu     320(%rsp), %xmm13
    movdqu     336(%rsp), %xmm14
    movdqu     352(%rsp), %xmm15
    vmresume   0  (%rsp)
    ret