ENTRY(reset_vector_entry)
 
SECTIONS
{ 
	/* Put the rest of the code "not too far away" from the reset vector:
	 	we're in 16bit mode and want to do a relative jump */ 
	. = 0xfffff000;
	.text.bootstrap BLOCK(4K) : ALIGN(4K)
	{
		*(.bootstrap)
	}

    . = 0xfffffff0;
	.text.resetvector :
	{
		*(.resetvector)
	}
}