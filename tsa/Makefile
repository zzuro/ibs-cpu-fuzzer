EXTRACTOR_NAME := tsa
SCANNER_NAME := tsa_scanning

# Build both modules
obj-m += $(EXTRACTOR_NAME).o
obj-m += $(SCANNER_NAME).o

# Extractor is single-file: tsa.c -> tsa.ko
# Scanner is multi-file: tsa_scanning_main.c + opcode_wrapper.c -> tsa_scanning.ko
$(SCANNER_NAME)-y := tsa_scanning_main.o opcode_wrapper.o

# Extra compiler flags for these modules
ccflags-y += -O3
ccflags-y += -march=native
ccflags-y += -fno-tree-vectorize
ccflags-y += -ffp-contract=off

CFLAGS_tsa.o += -msse -msse2 -O3 -march=native -fno-tree-vectorize -ffp-contract=off
CFLAGS_tsa_scanning_main.o += -msse -msse2 -O3 -march=native -fno-tree-vectorize -ffp-contract=off
CFLAGS_opcode_wrapper.o += -msse -msse2 -O3 -march=native -fno-tree-vectorize -ffp-contract=off

# CRITICAL FIX: Tell objtool to completely ignore these modules
OBJECT_FILES_NON_STANDARD_$(EXTRACTOR_NAME).o := y
OBJECT_FILES_NON_STANDARD_$(SCANNER_NAME).o := y

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: all clean insmod insmod-scan rmmod-ext rmmod-scan

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

insmod: all
	@echo "[+] Clearing kernel ring buffer (dmesg -C)..."
	@sudo dmesg -C
	@echo "[+] Removing old extractor module if it exists..."
	@-sudo rmmod $(EXTRACTOR_NAME) 2>/dev/null || true
	@echo "[+] Inserting $(EXTRACTOR_NAME).ko..."
	@sudo insmod $(EXTRACTOR_NAME).ko
	@echo "[+] Waiting for kthread to complete the extraction..."
	@sleep 1
	@echo "============================================================"
	@echo "                  EXTRACTOR KERNEL OUTPUT                   "
	@echo "============================================================"
	@sudo dmesg

insmod-scan: all
	@echo "[+] Clearing kernel ring buffer (dmesg -C)..."
	@sudo dmesg -C
	@echo "[+] Removing old scanner module if it exists..."
	@-sudo rmmod $(SCANNER_NAME) 2>/dev/null || true
	@echo "[+] Inserting $(SCANNER_NAME).ko..."
	@sudo insmod $(SCANNER_NAME).ko
	@echo "[+] Waiting for kthread to complete the scan..."
	@sleep 1
	@echo "============================================================"
	@echo "                   SCANNER KERNEL OUTPUT                    "
	@echo "============================================================"
	@sudo dmesg

rmmod-ext:
	@echo "[+] Removing $(EXTRACTOR_NAME)..."
	@sudo rmmod $(EXTRACTOR_NAME)

rmmod-scan:
	@echo "[+] Removing $(SCANNER_NAME)..."
	@sudo rmmod $(SCANNER_NAME)