#!/bin/bash

rm -rf build
mkdir build

echo "################################"
echo "       BUILDING GUEST OS"
echo "################################"

# build the 32 bit code
clang pagetables_32.c -o build/pagetables_32.o -c -m32 -std=gnu99 -ffreestanding -O2 -Wall -Wextra -static
gcc -c start.S -o build/start.o -static

# build the 64 bit code
clang main.c -o build/main.o -c -std=gnu99 -ffreestanding -O2 -Wall -Wextra -static

# Now do a hack for linking the 32 and 64 bit code together:
# objcopy both to 64 bit, link, and objcopy to 32 bot afterwards
objcopy -O elf32-x86-64 -I elf32-i386 build/start.o build/start_32.o
objcopy -O elf32-x86-64 -I elf32-i386 build/pagetables_32.o build/pagetables_32_32.o
objcopy -O elf32-x86-64 -I elf64-x86-64 build/main.o build/main_32.o
gcc -T link.ld -o build/kernel.bin -ffreestanding -O2 -nostdlib build/start_32.o build/pagetables_32_32.o build/main_32.o -Xlinker -m -Xlinker elf32_x86_64
objcopy -O elf32-i386 -I elf32-x86-64 build/kernel.bin build/kernel.bin

echo "################################"
echo "    BUILDING USERLAND LOADER"
echo "################################"

# Build the userland loader which loads the ELF file into hv
clang -Wall loader.c -o build/loader -I ../../include

echo "Done"