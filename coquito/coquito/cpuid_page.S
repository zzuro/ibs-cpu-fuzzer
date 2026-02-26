.section .cpuid
.global cpuid_page
.type cpuid_page, @object

.align 4096
cpuid_page:
.fill 4096, 1, 0x7c   /* Random value, used for debugging */
.size cpuid_page, . - cpuid_page
