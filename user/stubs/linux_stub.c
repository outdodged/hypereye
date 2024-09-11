#include <sys/mman.h>
#include <unistd.h>

#define PAGE_SIZE 0x1000

int main() {
    void*   mem;
    
    mem = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    while(1) {
        syscall(0x41414141, mem);
    }

    return 0;
}