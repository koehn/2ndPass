#include "include/MopOpenSSH.h"
#include <CommonCrypto/CommonCryptor.h>
int mop_aes_ctr(const uint8_t *key, const uint8_t *iv, const uint8_t *input, size_t count, uint8_t *output) {
 CCCryptorRef cryptor = NULL;
 CCCryptorStatus status = CCCryptorCreateWithMode(kCCDecrypt, kCCModeCTR, kCCAlgorithmAES, ccNoPadding, iv, key, 32, NULL, 0, 0, kCCModeOptionCTR_BE, &cryptor);
 if (status != kCCSuccess) return status;
 size_t written = 0;
 status = CCCryptorUpdate(cryptor, input, count, output, count, &written);
 CCCryptorRelease(cryptor);
 return status == kCCSuccess && written == count ? 0 : -1;
}
