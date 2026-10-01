OpenSSH portable V_10_0_P1: openbsd-compat/{bcrypt_pbkdf.c,blowfish.c,blf.h}.
Upstream: https://github.com/openssh/openssh-portable/tree/V_10_0_P1/openbsd-compat
Licenses are retained in each source. Include those notices in binary distributions.
Local compatibility headers substitute CommonCrypto SHA-512 and memset_s; aes.c wraps CommonCrypto AES-CTR. The bcrypt success path additionally clears SHA-512 scratch buffers. No algorithm changes.
