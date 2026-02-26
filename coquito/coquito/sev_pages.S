.section .sev_pages

.global coquito_ghcb
.type coquito_ghcb, @object

.global coquito_cpuid
.type coquito_cpuid, @object

.global coquito_secrets
.type coquito_secrets, @object

.global coquito_caa
.type coquito_caa, @object


.align 4096
coquito_ghcb:
.skip 4096    /* GHCB, a single page */
.size coquito_ghcb, . - coquito_ghcb

.align 4096
coquito_cpuid:
.skip 4096    /* CPUID page, a single page */
.size coquito_cpuid, . - coquito_cpuid

.align 4096
coquito_secrets:
.skip 4096    /* Secrets page, again a single page  */
.size coquito_secrets, . - coquito_secrets

.align 4096
coquito_caa:
.skip 4096    /* CAA page to talk to COCONUT, a single page */
.size coquito_caa, . - coquito_caa
