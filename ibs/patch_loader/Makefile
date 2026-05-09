obj-m += ucode_loader.o
ucode_loader-y := patch_loader.o nmi.o apic.o page_table_stuff.o opcode_wrappers.o ibs_logger.o

# Only this file is allowed to contain AVX/FPU code
CFLAGS_opcode_wrappers.o += $(CC_FLAGS_FPU) -mavx2
CFLAGS_REMOVE_opcode_wrappers.o += $(CC_FLAGS_NO_FPU)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

insmod: all
	sudo insmod ucode_loader.ko

log:
	dmesg -w