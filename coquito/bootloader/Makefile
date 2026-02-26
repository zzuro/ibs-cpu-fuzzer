.PHONY: all clean mrproper

all: vector.bin

clean:
		# Do nothing, there are no intermediate object files

mrproper: clean
		rm -f vector.bin

vector.bin: ResetVector.iii Ia16/Init16.asm Ia16/Real16ToFlat32.asm Ia16/ResetVectorVtf0.asm DebugDisabled.asm X64/IntelTdxMetadata.asm X64/OvmfSevMetadata.asm Ia32/AmdSev.asm Ia32/Flat32ToFlat64.asm Ia32/IntelTdx.asm Ia32/PageTables64.asm BootControlBlock.asm
		nasm -f bin -o $@ ResetVector.iii
		# Pad to 16 bytes (so that we know that the file really does end at address 0xffffffff and not a few bytes before)
		python3 pad.py $@
