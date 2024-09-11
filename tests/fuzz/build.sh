#!/bin/bash

rm -rf build
mkdir build

clang -Wall fuzz_ioctl_one.c -I../../include -o build/fuzz_ioctl_one
clang -Wall fuzz_ioctl_datarace.c -I../../include -o build/fuzz_ioctl_datarace