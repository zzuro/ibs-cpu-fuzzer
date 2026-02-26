#include "ktypes.h"

/**
 * @file All content of this file is heavily based on the Intel AES-NI whitepaper (https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf)
 */

/**
    @param[in] userkey The "small" 128-bit key
    @param[out] key A 16*11 bytes buffer to write the expanded key to
 */
void AES_128_Key_Expansion(const u8 *userkey, u8 *key);

/**
    @param[in] in Pointer to the PLAINTEXT
    @param[out] out Pointer to the CIPHERTEXT buffer
    @param length Text length in bytes
    @param key Pointer to the expanded key schedule
    @param number_of_rounds Number of AES rounds 10,12 or 14

 */
void AES_ECB_encrypt(u8 *in, u8 *out, unsigned long length, const u8* key, unsigned int number_of_rounds);
