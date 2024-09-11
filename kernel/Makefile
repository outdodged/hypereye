TARGET		= HYPEREYE

MY_CFLAGS += -g # -DDEBUG
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

EXTRA_CFLAGS=-I$(PWD)/include -I$(PWD)/../include

obj-m		+= $(TARGET).o
$(TARGET)-objs := ./src/guest.o ./src/ioctl.o ./src/memory.o ./src/svm/svm.o ./src/svm/svm_ops.o ./src/svm/vmrun.o ./src/svm/svm_kvm_hook.o ./src/HYPEREYE.o ./src/x86/x86.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean

