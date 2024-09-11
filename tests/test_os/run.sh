#!/bin/bash

./build.sh

echo "################################"
echo "     INSERT KERNEL MODULE"
echo "################################"
cd ../..
./build.sh
sudo insmod kernel/HYPEREYE.ko
cd tests/test_os

echo "################################"
echo "      RUNNING GUEST OS"
echo "################################"
cd build
sudo ./loader kernel.bin
cd ..

sudo rmmod HYPEREYE