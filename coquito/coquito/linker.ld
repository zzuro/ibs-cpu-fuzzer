/**
 * Taken from https://wiki.osdev.org/Bare_Bones
   Licensed under Public Domain License, see https://wiki.osdev.org/OSDev_Wiki:License
 */

ENTRY(_start)

SECTIONS
{
	/* This is where we expect to be loaded. */
	. = 0xffc04000;

	.text BLOCK(4K) : ALIGN(4K)
	{
		/* *(.multiboot) */
		*(.text)
		*(.sev_pages)
		*(.cpuid)
		*(.caa)
		*(.rodata)
	}

	 /* Remember where the ROM image ends so we can place .data payload there */
  	__rom_after_text = ALIGN(4K);

	. = 0x900000;
  	.stack_kernel_c (NOLOAD) : ALIGN(16) {
    	*(.stack_kernel_c)
  	}

	. = 0x908000;
	.page_table (NOLOAD) : ALIGN(4096) { *(.page_table) }

	. = 0x910000;
	.gdt (NOLOAD) : ALIGN(4096) { *(.gdt) }
	.idt (NOLOAD) : ALIGN(4096) { *(.idt) }


	/* Initialized data: lives in RAM, contents stored in ROM at __rom_after_text */
  	.data : AT(__rom_after_text) ALIGN(16) {
  	  __data_start = .;
  	  *(.data*)
  	  __data_end = .;
  	}
	
  	__data_load = LOADADDR(.data);
  	__rom_after_text = __rom_after_text + SIZEOF(.data);

  	/* BSS: RAM, zero at boot */
  	.bss (NOLOAD) : ALIGN(16) {
  	  __bss_start = .;
  	  *(.bss*)
  	  *(COMMON)
  	  __bss_end = .;
  	}

	/DISCARD/ : {
		*(.dynamic) *(.dynsym) *(.dynstr) *(.dynbss)
		*(.hash) *(.gnu.hash)
		*(.note.*)
		*(.interp)
		*(.rela.dyn .got .got.plt .data.rel .bss)
	}
}