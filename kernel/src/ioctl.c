#include <ioctl.h>
#include <stddef.h>
#include <HYPEREYE_defs.h>
#include <guest.h>
#include <memory.h>
#include <svm/svm.h>

#include <asm/pgtable.h>
#include <linux/slab.h> 
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/rwsem.h>
#include <linux/highmem.h>

// TODO: check if this is secure
DEFINE_MUTEX(fuzz_mmap_mutex);
uint64_t* 	fuzz_mmap;
uint64_t	fuzz_map_size;

static long unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long argp) {
	uint64_t					id;
	uint64_t					g_type;
	unsigned int				i;
	internal_guest				*g;
	internal_vcpu				*vcpu;
	internal_vcpu				*current_vcpu;
	internal_memory_region		*current_memory_region;
	uint64_t*					breakpoints_array;
	internal_breakpoint*		bp;

	user_arg_registers 			regs;
	user_memory_region			memory_region;
	user_vcpu_guest_id			id_data;
	user_breakpoints			breakpoints;

	id							= 0;
	g_type						= 0;
	g 							= NULL;
	vcpu  						= NULL;
	current_vcpu 				= NULL;
	current_memory_region 		= NULL;
	
	printk(DBG "Got ioctl cmd: 0x%x\n", cmd);
	
	switch (cmd) {
		case HYPEREYE_IOCTL_CREATE_GUEST:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			if (copy_from_user((void*)&g_type, (void __user *)argp, sizeof(uint64_t))) {
				return -EFAULT;
			}

			if (g_type == GUEST_CREATE_NEW) {
				g = create_guest();
			}
			else if (g_type == GUEST_CREATE_KVM_REC) {
				g = simple_copy_guest(&kvm_guest);
			} else {
				return -EFAULT;
			}

			if (g == NULL) {
				destroy_guest(g);
				return -ENOMEM;
			}

			guest_list_lock();

			printk(DBG "g: 0x%lx\n", (unsigned long)g);
			printk(DBG "insert\n");

			if (insert_new_guest(g)) {
				guest_list_unlock();
				destroy_guest(g);
				return -ENOMEM;
			}

			guest_list_unlock();

			// Return the guest ID to the user.
			if (copy_to_user((void __user *)argp, (void*)&g->id, sizeof(uint64_t))) {
				destroy_guest(g);
				return -EFAULT;
			}

			break;
		
		case HYPEREYE_IOCTL_DESTROY_GUEST:
			TEST_PTR(argp, unsigned long,,-EFAULT)
			
			if (copy_from_user((void*)&id, (void __user *)argp, sizeof(uint64_t))) {
				return -EFAULT;
			}

			guest_list_lock();

			g = map_guest_id_to_guest(id);
			TEST_PTR(g, internal_guest*, guest_list_unlock(), -EINVAL)

			// Aquire a write lock here in order to prevent VCPUs from running.
			guest_vcpu_write_lock(g);

			destroy_guest(g);

			guest_list_unlock();
			
			break;
			
		case HYPEREYE_IOCTL_CREATE_VCPU:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			if (copy_from_user((void*)&id_data, (void __user *)argp, sizeof(user_vcpu_guest_id))) {
				return -EFAULT;
			}

			guest_list_lock();
			g = map_guest_id_to_guest(id_data.guest_id);
			guest_list_unlock();
			TEST_PTR(g, internal_guest*,, -EINVAL)

			guest_vcpu_write_lock(g);
			
			vcpu = create_vcpu(g);
			
			if (insert_new_vcpu(vcpu, g)) {
				destroy_vcpu(vcpu);
				guest_vcpu_write_unlock(g);
				return -ENOMEM;
			}

			id_data.vcpu_id = vcpu->id;

			// Return the VCPU ID to the user.
			if (copy_to_user((void __user *)argp, (void*)&id_data, sizeof(user_vcpu_guest_id))) {
				destroy_vcpu(vcpu);
				guest_vcpu_write_unlock(g);
				return -ENOMEM;
			}

			guest_vcpu_write_unlock(g);

			break;
			
		case HYPEREYE_IOCTL_SET_REGISTERS:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			if (copy_from_user((void*)&regs, (void __user *)argp, sizeof(user_arg_registers))) {
				return -EFAULT;
			}

			guest_list_lock();
			g = map_guest_id_to_guest(regs.guest_id);
			guest_list_unlock();
			TEST_PTR(g, internal_guest*,, -EINVAL)
			
			guest_vcpu_read_lock(g);
			current_vcpu = map_vcpu_id_to_vcpu(regs.vcpu_id, g);
			HYPEREYE_ops.set_vcpu_registers(current_vcpu, &regs);
			guest_vcpu_read_unlock(g);
			
			break;
			
		case HYPEREYE_IOCTL_GET_REGISTERS:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			if (copy_from_user((void*)&regs, (void __user *)argp, sizeof(user_arg_registers))) {
				return -EFAULT;
			}

			guest_list_lock();
			g = map_guest_id_to_guest(regs.guest_id);
			guest_list_unlock();
			TEST_PTR(g, internal_guest*,, -EINVAL)

			guest_vcpu_read_lock(g);
			current_vcpu = map_vcpu_id_to_vcpu(regs.vcpu_id, g);
			HYPEREYE_ops.get_vcpu_registers(current_vcpu, &regs);
			guest_vcpu_read_unlock(g);

			if (copy_to_user((void __user *)argp, (void*)&regs, sizeof(user_arg_registers))) {
				return -EFAULT;
			}

			break;
			
		case HYPEREYE_IOCTL_VCPU_RUN:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			printk(DBG "VCPU_RUN\n");

			if (copy_from_user((void*)&id_data, (void __user *)argp, sizeof(user_vcpu_guest_id))) {
				return -EFAULT;
			}

			guest_list_lock();
			g = map_guest_id_to_guest(id_data.guest_id);
			guest_list_unlock();
			TEST_PTR(g, internal_guest*,, -EINVAL)

			guest_vcpu_read_lock(g);
			current_vcpu = map_vcpu_id_to_vcpu(id_data.vcpu_id, g);
			HYPEREYE_ops.run_vcpu(current_vcpu, g);
			guest_vcpu_read_unlock(g);
			
			break;

		case HYPEREYE_SET_MEMORY_REGION:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			if (copy_from_user((void*)&memory_region, (void __user *)argp, sizeof(user_memory_region))) {
				return -EFAULT;
			}

			guest_list_lock();
			g = map_guest_id_to_guest(memory_region.guest_id);
			TEST_PTR(g, internal_guest*, guest_list_unlock(), -EINVAL)

			current_memory_region = kzalloc(sizeof(internal_memory_region), GFP_KERNEL);
			TEST_PTR(current_memory_region, internal_memory_region*, guest_list_unlock(), -ENOMEM);

			current_memory_region->userspace_addr 	= memory_region.userspace_addr;
			current_memory_region->guest_addr 		= memory_region.guest_addr;
			current_memory_region->size 			= memory_region.size;
			current_memory_region->is_mmio			= memory_region.is_mmio;
			current_memory_region->is_cow			= memory_region.is_cow;
			current_memory_region->pages 			= kzalloc((int)((memory_region.size / PAGE_SIZE) + 1) * sizeof(struct page *), GFP_KERNEL);
			current_memory_region->modified_pages	= kzalloc((int)((memory_region.size / PAGE_SIZE) + 1) * sizeof(void*), GFP_KERNEL);

			// First check if there already is a memory region which would overlap with the new one
			mmu_add_memory_region(g->mmu, current_memory_region);

			guest_list_unlock();

			break;

		case HYPEREYE_BEGIN_KVM_RECORD:
			HYPEREYE_ops.register_kvm_record_handler();
			break;

		case HYPEREYE_END_KVM_RECORD:
			HYPEREYE_ops.deregister_kvm_record_handler();
			break;

		case HYPEREYE_ROLLBACK:
			// TODO
			break;

		case HYPEREYE_SET_FUZZ_CNTR_REGION:
			TEST_PTR(argp, unsigned long,,-EFAULT)
			
			if (copy_from_user((void*)&id, (void __user *)argp, sizeof(uint64_t))) {
				return -EFAULT;
			}

			guest_list_lock();

			g = map_guest_id_to_guest(id);
			TEST_PTR(g, internal_guest*, guest_list_unlock(), -EINVAL)

			// Aquire a write lock here in order to prevent VCPUs from running.
			guest_vcpu_write_lock(g);

			g->fuzzing_coverage = fuzz_mmap;
			g->fuzzing_coverage_size = fuzz_map_size;
			
			mutex_unlock(&fuzz_mmap_mutex);
			guest_vcpu_write_unlock(g);
			guest_list_unlock();

			break;

		case HYPEREYE_SET_BREAKPOINTS:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			if (copy_from_user((void*)&breakpoints, (void __user *)argp, sizeof(user_breakpoints))) {
				return -EFAULT;
			}

			guest_list_lock();
			g = map_guest_id_to_guest(breakpoints.guest_id);
			guest_list_unlock();
			TEST_PTR(g, internal_guest*,, -EINVAL)

			if (breakpoints.sz > MAX_BREAKPOINTS_LIST_LEN) return -EFAULT;

			breakpoints_array = (uint64_t*) kmalloc(breakpoints.sz, GFP_KERNEL);

			if (copy_from_user((void*)&breakpoints_array[0], (void __user *)breakpoints.addr, breakpoints.sz)) {
				return -EFAULT;
			}

			// Force all VCPUs to exit so they all see the breakpoints at the same time
			guest_vcpu_write_lock(g);
			if (breakpoints.virt) {
				for (i = 0; i < (unsigned int)(breakpoints.sz / sizeof(uint64_t)); i++) {
					bp = find_breakpoint_by_gva(g, breakpoints_array[i]);
					if (bp == NULL) {
						printk(DBG "Insert virt BP at: 0x%lx\n", breakpoints_array[i]);
						HYPEREYE_ops.add_breakpoint_v(g, breakpoints_array[i]);
					}
				}
			}
			else {
				for (i = 0; i < (unsigned int)(breakpoints.sz / sizeof(uint64_t)); i++) {
					bp = find_breakpoint_by_gpa(g, breakpoints_array[i]);
					if (bp == NULL) {
						printk(DBG "Insert phys BP at: 0x%lx\n", breakpoints_array[i]);
						HYPEREYE_ops.add_breakpoint_p(g, breakpoints_array[i]);
					}
				}
			}

			guest_vcpu_write_unlock(g);

			kfree(breakpoints_array);

			break;
			
		default:
			printk(DBG "ioctl command not supported: 0x%x\n", cmd);
			return -EINVAL;
	}
	
	return 0;
}

static int mmap_fuzz(struct file *file, struct vm_area_struct *vma) {
	unsigned long address;
	unsigned long start;
	unsigned long length;
	size_t size;

	printk(DBG "mmap_fuzz\n");

	mutex_lock(&fuzz_mmap_mutex);

	size = vma->vm_end - vma->vm_start;
	
	fuzz_mmap = (uint64_t*)kzalloc(size, GFP_KERNEL);
	fuzz_map_size = size;

	address = (unsigned long)fuzz_mmap;

	if (fuzz_mmap == NULL) {
		printk(DBG "kmalloc failed!\n");
		return -ENOMEM;
	}

	if ((size > MAX_BREAKPOINTS_LIST_LEN) || (vma->vm_pgoff != 0)) {
		printk(DBG "fuzz mmap failed size check\n");
		return -EINVAL;
	}

	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;

	start = vma->vm_start;
	length = size;
	
	while (length > 0) {
		unsigned long pfn = __pa(address) >> 12;
		
		if (remap_pfn_range(vma, start,
							pfn,
							PAGE_SIZE,
							vma->vm_page_prot)) {
			printk(DBG "remap_pfn_range failed\n");
			return -EAGAIN;
		}
		start   += PAGE_SIZE;
		address += PAGE_SIZE;
		length  -= PAGE_SIZE;
	}
	printk(DBG "remap_pfn_range done\n");

	return 0;
}

static struct proc_ops proc_ctl_fops = {
	.proc_ioctl = unlocked_ioctl,
};

static struct proc_ops proc_fuzz_fops = {
	.proc_mmap = mmap_fuzz,
};

void init_ctl_interface(){
    proc_create(PROC_PATH, 0, NULL, &proc_ctl_fops);
	proc_create(FUZZ_PATH, 0, NULL, &proc_fuzz_fops);
}

void finit_ctl_interface(){
    remove_proc_entry(PROC_PATH, NULL);
	remove_proc_entry(FUZZ_PATH, NULL);
}
