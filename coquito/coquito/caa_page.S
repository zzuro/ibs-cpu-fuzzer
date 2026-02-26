.section .caa
.global caa_page
.type caa_page, @object

.align 4096
caa_page:
.fill 4096, 1, 0x5b   /* Random value, used for debugging */
.size caa_page, . - caa_page
