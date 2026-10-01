#include <stddef.h>
#include <stdint.h>
int bcrypt_pbkdf(const char *, size_t, const uint8_t *, size_t, uint8_t *, size_t, unsigned int);
int mop_aes_ctr(const uint8_t *key, const uint8_t *iv, const uint8_t *input, size_t count, uint8_t *output);
