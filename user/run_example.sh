#!/bin/bash

cd ..
./build.sh
cd user

echo "################################"
echo "     INSERT KERNEL MODULE"
echo "################################"
sudo insmod ../kernel/HYPEREYE.ko

echo "################################"
echo "       RUN USERLAND TEST"
echo "################################"
sudo ../example
sudo rmmod HYPEREYE
