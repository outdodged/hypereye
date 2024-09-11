#include <x86/x86.h>

void (*x86_io_port_handlers[MAX_NUM_IO_PORTS])(int, uint32_t, uint16_t, uint32_t*);

int x86_handle_io(int in, uint32_t op_size, uint16_t port, uint32_t *eax) {

    // Check if we have registered a IO port handler first
    if (x86_io_port_handlers[port] == NULL) {
        printk(DBG "IO port handler for 0x%x not registered!\n", port);
        return -EINVAL;
    } else {
        x86_io_port_handlers[port](in, op_size, port, eax);
    }
    return 0;
}

void x86_dummy_io_handler(int in, uint32_t op_size, uint16_t port, uint32_t *eax) {
    // If this is an IN instruction: return 0
    if (in) *eax = 0;

    // Else: do nothing
}

void x86_handle_mmio(internal_vcpu *vcpu, gpa_t phys_guest, int is_write) {
    // Dummy handler
    // TODO: implement functionality
}