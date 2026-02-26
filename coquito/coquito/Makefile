.PHONY: all coquito clean mrproper

all: coquito.elf coquito_otheraddr.elf

CC=gcc
AS=as
OBJCOPY=objcopy
ISODIR=isodir

OBJS := boot.o kernel.o io.o serial.o interrupts.o interrupt_handlers.o interrupts_table.o sevsnp.o paging.o gdt.o gdt_data.o page_table.o sev_pages.o cpuid_page.o caa_page.o coquito_stack.o sse.o aes.o vectorops.o


# See https://stackoverflow.com/questions/26300819/why-gcc-compiled-c-program-needs-eh-frame-section
CFLAGS := -std=gnu99 -ffreestanding -mcmodel=large -mno-red-zone -mno-mmx -mno-sse -mno-sse2 -fno-asynchronous-unwind-tables -O0 -Werror -Wmissing-prototypes -Wall -Wextra -Wcast-qual -Wcast-align -Wstrict-aliasing -Wpointer-arith -Winit-self\
			-Wshadow -Wswitch-enum -Wstrict-prototypes -Wredundant-decls -Wfloat-equal -fno-pie

CFLAGS_AVX := -std=gnu99 -ffreestanding -mcmodel=large -mno-red-zone -fno-asynchronous-unwind-tables -O0 -Werror -Wmissing-prototypes -Wall -Wextra -Wcast-qual -Wcast-align -Wstrict-aliasing -Wpointer-arith -Winit-self\
			-Wshadow -Wswitch-enum -Wstrict-prototypes -Wredundant-decls -Wfloat-equal -fno-pie


clean:
	rm -rf *.o tmp_code

mrproper: clean
	rm -f coquito.elf coquito_otheraddr.elf coquito.bin coquito.iso coquito.idlebin
	rm -rf $(ISODIR) 


# Fully-fledged ELF
# See https://stackoverflow.com/questions/52865823/is-there-a-way-to-have-the-compiler-warn-err-if-an-attribute-section-is-not-defi
coquito.elf: $(OBJS)
	$(CC) -T linker.ld -Wl,--section-start=.text=0xffc04000 -o $@ -ffreestanding -O0 -nostdlib $^ -lgcc -static

# Simply coquito.elf but with a different load address
coquito_otheraddr.elf: $(OBJS)
	$(CC) -T linker.ld -Wl,--section-start=.text=0xffd00000 -o $@ -ffreestanding -O0 -nostdlib $^ -lgcc

# Flat binary
# See https://stackoverflow.com/questions/32002754/how-to-convert-elf-file-to-binary-file
coquito.bin: coquito.elf ../bootloader/vector.bin
	$(OBJCOPY) --dump-section .text=$@ coquito.elf
	bash -c 'dd if=/dev/null of=$@ bs=1 count=1 seek=$$(( 4194304 - $$(stat --printf="%s" ../bootloader/vector.bin) ))'
	cat ../bootloader/vector.bin >> $@
	# # Strip multiboot header (first 12 bytes)
	# dd if=coquito.bin.tmp of=$@ bs=4 skip=3

# Bootable self-standing image 
coquito.iso: coquito.elf
	mkdir -p $(ISODIR)/boot/grub
	cp $^ $(ISODIR)/boot/coquito.elf
	cp grub.cfg $(ISODIR)/boot/grub/grub.cfg
	grub-mkrescue -o $@ $(ISODIR)


bootstrapper.elf: bootstrapper.o reset_vector.o
	$(CC) -T bootstrapper.ld -o $@ -ffreestanding -O2 -nostdlib $^ -lgcc

bootstrapper.bin: bootstrapper.elf
	$(OBJCOPY) --dump-section .text.bootstrap=tmp_code.bin --dump-section .text.resetvector=resetvector.bin $^
	# Expand to fit (see https://unix.stackexchange.com/questions/196715/how-to-pad-a-file-to-a-desired-size)
	# The boostrapper is expected to be at 0xfffff000, and the reset vector has to be loaded at 0xff'ff'ff'f0, 16 bytes
	# before the end of the page
	dd if=/dev/null of=tmp_code.bin bs=1 count=1 seek=4080
	cat resetvector.bin >> tmp_code.bin
	# Now since the whole image will be loaded at adress 0xffc00000, we need to prepend the binary with padding
	# so that the reset vector code (and the main boostrapping code) are just at the right address.
	# Add 4190208 bytes (0xfffff000 - 0xffc00000) of data before the actual meat
	dd if=/dev/zero bs=1 count=4190208 of=$@
	cat tmp_code.bin >> $@

coquito.idlebin:
	# 4 MiB minus 16 bytes for the reset code
	# Set image full of nops (works if we put something else too, just make it
	# explicit)
	dd if=/dev/zero bs=1 count=4194288 | tr "\000" "\220" > coquito.idlebin
	# Idle loop, assembled online using https://defuse.ca/online-x86-assembler.htm#disassembly
	/usr/bin/echo -ne '\xfa\xf4\xeb\xfd' >> coquito.idlebin


%.o: %.S
	$(AS) $^ -o $@

%.o: %.c
	$(CC) -c $^ -o $@ $(CFLAGS)

%.o: %.isr
	# Compile interrupt service routine, disable "exotic" registers
	# -x c because GCC thinks it's a linker (?) file because of the
	# unusual extension.
	# See https://stackoverflow.com/questions/2223095/gcc-compiling-invalid-c-code
	$(CC) -c -x c $^ -o $@ $(CFLAGS) -mgeneral-regs-only

%.o: %.sse
	# Build with SSE/AVX support
	# !!! Enforce runtime stack re-alignement to 16 bytes!
	# We might want the whole system to use 16-bytes alignement if we make heavy use of SSE/AVX
	# (which most likey will not be the case)
	$(CC) -x c -c $^ -mstackrealign -march=native -o $@ $(CFLAGS_AVX)