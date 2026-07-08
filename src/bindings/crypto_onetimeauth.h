int crypto_onetimeauth(unsigned char *out,
                       const unsigned char *in,
                       unsigned long long inlen,
                       const unsigned char *k);

int crypto_onetimeauth_verify(const unsigned char *h,
                              const unsigned char *in,
                              unsigned long long inlen,
                              const unsigned char *k);

size_t crypto_onetimeauth_bytes(void);
size_t crypto_onetimeauth_keybytes(void);
