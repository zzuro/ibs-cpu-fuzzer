obj-m += ibs_final.o
ibs_final-y := ibs.o nmi.o apic.o page_table_stuff.o opcode_wrappers.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

insmod: all
	sudo insmod ibs_final.ko

log:
	tail -f /var/log/messages
