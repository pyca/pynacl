
size_t crypto_stream_chacha20_keybytes();

size_t crypto_stream_chacha20_noncebytes();

size_t crypto_stream_chacha20_messagebytes_max();

size_t crypto_stream_chacha20_ietf_keybytes();

size_t crypto_stream_chacha20_ietf_noncebytes();

size_t crypto_stream_chacha20_ietf_messagebytes_max();

int crypto_stream_chacha20(unsigned char *c, unsigned long long clen,
                       const unsigned char *n, const unsigned char *k);

int crypto_stream_chacha20_ietf(unsigned char *c, unsigned long long clen,
                            const unsigned char *n, const unsigned char *k);

int crypto_stream_chacha20_xor_ic(unsigned char *c, const unsigned char *m,
                              unsigned long long mlen,
                              const unsigned char *n, uint64_t ic,
                              const unsigned char *k);

int crypto_stream_chacha20_ietf_xor_ic(unsigned char *c, const unsigned char *m,
                                   unsigned long long mlen,
                                   const unsigned char *n, uint32_t ic,
                                   const unsigned char *k);

int crypto_stream_chacha20_xor(unsigned char *c, const unsigned char *m,
                           unsigned long long mlen, const unsigned char *n,
                           const unsigned char *k);

int crypto_stream_chacha20_ietf_xor(unsigned char *c, const unsigned char *m,
                                unsigned long long mlen, const unsigned char *n,
                                const unsigned char *k);

void crypto_stream_chacha20_keygen(unsigned char *k);