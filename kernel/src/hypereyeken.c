#include <svm/svm.h>
#include <svm/svm_ops.h>
#include <ioctl.h>
#include <stddef.h>

#include <linux/init.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");

int HYPEREYE_initialized = 0;

static int __init HYPEREYE_init(void) {
	printk(DBG "Loaded HYPEREYE kernel module\n");

    // Detect on which platform HYPEREYE is running on.
    //if (svm_check_support())
        init_svm_HYPEREYE_ops();

    // If we are on no supported platform, unload the module
    if (HYPEREYE_initialized == 0) {
        printk(DBG "No supported platform detected!\n");
        return -1;
    }

    // Initialize data structures
    //memset(&g_guests[0], 0, sizeof(g_guests));

	init_ctl_interface();
	return 0;
}

static void __exit HYPEREYE_exit(void) {
	printk(DBG "Unloaded HYPEREYE kernel module\n");

    destroy_all_guests();

	finit_ctl_interface();
}

module_init(HYPEREYE_init);
module_exit(HYPEREYE_exit);