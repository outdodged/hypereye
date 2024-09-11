# HYPEREYE: Mini AMD Hypervisor

A small AMD SVM (AMD Secure Virtual Machine) Hypervisor for Linux systems. It provides a clear interface for creating guests, setting registers and donating memory to the guest. HYPEREYE is intended to be a minimal hypervisor without capabilities such as complex device emulation.
It is primarily **supposed to show how AMD SVM is used and how a hypervisor, such as KVM, works under the hood**. Therefore, booting of complex systems, such as Linux or Windows, is not supported. In order to be still a comprehensive und easily understandable, HyperEye is intended to have a small codebase.

HyperEye's backend and SVM defs have some functions from Kraken and other projects
This project is a reworked and better optimization of other hypervisors out there with new features aswell.

I am happy about any suggestions in order to improve this project! And if you find a bug, please report it. There still might be a few in here, since the project is still in development.

## Features
The features HYPEREYE provides are:
 - Donating userspace memory to the guest
 - Setting registers
 - Set when a VM should be intercepted
 - Getting the VM interception information

## Example API usage
A small example for using HYPEREYE:
```c
#define TEST_IOCTL_RET(x) if (x) return EXIT_FAILURE;

...

TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_CREATE_GUEST))
	
// Create a VCPU for the guest
TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_CREATE_VCPU))
	
// Donate the page to the guest
guest_page = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, ctl_fd, 0);
memset(guest_page, 0xf4, getpagesize());
	
// Get the registers and set EBX and ECX
TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_GET_REGISTERS, &regs))
regs.rbx = 4;
regs.rcx = 5;
TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_SET_REGISTERS, &regs))
	
// Run the VCPU
TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_VCPU_RUN, &exit))
	
printf("Exit reason: 0x%lx\n", exit.exitcode);
printf("Exit info 1: 0x%lx\n", exit.exitinfo1);
printf("Exit info 2: 0x%lx\n", exit.exitinfo2);

...

```
The above example creates a guest and executes a `HLT` instruction, which exits the guest and will be intercepted by the hypervisor.
A more complete example can be found in the `user` folder. Userland code should include `HYPEREYE_defs.h` in the `include` folder. This header file is shared by both user- and kernelspace.
Currently, the following self-explaining IOCTLs are provided:
```c
HYPEREYE_IOCTL_CREATE_GUEST
HYPEREYE_IOCTL_CREATE_VCPU
HYPEREYE_IOCTL_SET_REGISTERS
HYPEREYE_IOCTL_GET_REGISTERS
HYPEREYE_IOCTL_VCPU_RUN
HYPEREYE_IOCTL_DESTROY_GUEST
HYPEREYE_SET_INTERCEPT_REASONS
```

## Building: Ubuntu
Install the dependencies via:
```
sudo apt install gcc make linux-headers-$(uname -r)
```
In order to build HYPEREYE, clone the repository and execute:
```
./build.sh
```

## TODO
 - Support for multiple VCPUs and vAPIC support
 - Log of all accessed pages
 - Check if number of VCPUs is within number of phyiscal cores
 - IO permissions
 - CPU reset: enter realmode instead of protected mode, move code to userland
 - Add automated tests
 - Guest test OS
 - guest virtual to guest phyiscal address
 - ASID generation
 - removal of unnecessary TEST_PTR calls

 - All exitcodes and instruction intercept definitions
 - MSR intercept handling
 - instruction intercept handling

## DONE
 - Lazy faulting
 - MMU abtraction
 - Arch-dependence abstraction
 - Copy-on-write
 - ioctl fuzzing code for a single guest
 - Breakpoints
 - Event injection
 - VMCB state caching
  - change pointers to be like in the Linux kernel
  - Fully included qemu cfg for easy vm setup

## IDEAS
 - converage-guided fuzzing with libfuzzer: User breakpoints & shared page in kernel
    - kernel module traces the breakpoints and increments counters in the shared page array accordingly
    - userland gets passes these counter to libfuzzer runtime
 - load qcow2 image of a booted system (use snapshots to recover guest state)
    - no need to 
 - nested hypervisor fuzzing
    - nested hypervisor functions (such as VMRUN, etc are emulated)
    - fuzz these instructions in order to find vulnerbilities
