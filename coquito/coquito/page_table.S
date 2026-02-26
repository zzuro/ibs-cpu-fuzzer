.section .page_table
.global paging_space
.type paging_space, @object

.align 4096
paging_space:
.skip 4096*16    /* Leave 16 pages for the page table */
.size paging_space, . - paging_space
