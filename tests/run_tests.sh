#!/bin/bash

rm -rf output
mkdir output

cd ..
./build.sh
cd tests

echo "################################"
echo "     INSERT KERNEL MODULE"
echo "################################"
sudo insmod ../kernel/HYPEREYE.ko

echo "################################"
echo "         BUILDING TESTS"
echo "################################"
clang -Wall -I../include testcases/cow.c -o output/cow
clang -Wall -I../include testcases/infinite_loop.c -o output/infinite_loop
clang -Wall -I../include testcases/multiple_guests.c -o output/multiple_guests
clang -Wall -I../include testcases/breakpoints.c -o output/breakpoints
clang -Wall -I../include testcases/tracing.c -o output/tracing

echo "################################"
echo "         RUNNING TESTS"
echo "################################"
cd output
#echo "[TEST]: COW"
#sudo ./cow > cow.output
#diff cow.output ../testcases/cow.output
#if (( $? != 0 )); then
#    echo "[TEST FAILED]"
#else
#    echo "[TEST PASSED]"
#fi


#echo "[TEST]: INFINITE LOOP"
#sudo ./infinite_loop
#echo "[TEST PASSED]"


#echo "[TEST]: MULTIPLE GUESTS"
#sudo ./multiple_guests > multiple_guests.output
#diff multiple_guests.output ../testcases/multiple_guests.output
#if (( $? != 0 )); then
#    echo "[TEST FAILED]"
#else
#    echo "[TEST PASSED]"
#fi


#echo "[TEST]: BREAKPOINTS"
#sudo ./breakpoints > breakpoints.output
#diff breakpoints.output ../testcases/breakpoints.output
#if (( $? != 0 )); then
#    echo "[TEST FAILED]"
#else
#    echo "[TEST PASSED]"
#fi


echo "[TEST]: KVM TRACING"
sudo ./tracing > tracing.output
diff tracing.output ../testcases/tracing.output
if (( $? != 0 )); then
    echo "[TEST FAILED]"
else
    echo "[TEST PASSED]"
fi

# Cleanup
sudo rmmod HYPEREYE