#include <CommonCrypto/CommonDigest.h>
#define crypto_hash_sha512_BYTES CC_SHA512_DIGEST_LENGTH
static inline int crypto_hash_sha512(unsigned char *out, const void *in, unsigned long long len) { return CC_SHA512(in, (CC_LONG)len, out) ? 0 : -1; }
