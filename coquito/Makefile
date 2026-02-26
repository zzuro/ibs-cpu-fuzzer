.PHONY: all clean mrproper 

all: multi_coquito.ovmf

clean:
	$(MAKE) -C bootloader clean
	$(MAKE) -C stage2 clean
	$(MAKE) -C coquito clean

mrproper: clean
	rm -f *.ovmf
	$(MAKE) -C bootloader mrproper
	$(MAKE) -C stage2 mrproper
	$(MAKE) -C coquito mrproper

bootloader/vector.bin:
	$(MAKE) -C bootloader vector.bin

stage2/stage2.elf:
	$(MAKE) -C stage2 stage2.elf

coquito/coquito.elf:
	$(MAKE) -C coquito coquito.elf

coquito/coquito_otheraddr.elf:
	$(MAKE) -C coquito coquito_otheraddr.elf

multi_coquito.ovmf: bootloader/vector.bin stage2/stage2.elf coquito/coquito.elf coquito/coquito_otheraddr.elf
	python3 image_build.py -b bootloader/vector.bin -s stage2/stage2.elf -c coquito/coquito.elf -c coquito/coquito_otheraddr.elf $@
