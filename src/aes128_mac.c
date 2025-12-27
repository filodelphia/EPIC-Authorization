// aes128_mac.c
#include <stdint.h>
#include <string.h>
#include <openssl/aes.h>

/*
 * Stateless AES-128 MAC used by the P4 extern.
 * key: 16-byte AES key
 * msg: 16-byte message block
 * mac_out: 32-bit MAC (first 4 bytes of ciphertext, big-endian)
 */

typedef struct {
    // No per-instance state for now; you can extend if needed.
    int dummy;
} aes128_mac_state_t;

void aes128_mac_t_apply(aes128_mac_state_t *state,
                        const uint8_t key[16],
                        const uint8_t msg[16],
                        uint32_t *mac_out)
{
    (void)state; // unused

    AES_KEY aes_key;
    uint8_t ct[16];

    // Initialize AES key schedule
    AES_set_encrypt_key(key, 128, &aes_key);

    // Encrypt single 16-byte block
    AES_encrypt(msg, ct, &aes_key);

    // Take first 4 bytes as MAC (big endian)
    *mac_out = ((uint32_t)ct[0] << 24) |
               ((uint32_t)ct[1] << 16) |
               ((uint32_t)ct[2] << 8)  |
               ((uint32_t)ct[3]);
}
