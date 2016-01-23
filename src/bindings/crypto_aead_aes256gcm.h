
size_t crypto_aead_aes256gcm_keybytes();
size_t crypto_aead_aes256gcm_nsecbytes();
size_t crypto_aead_aes256gcm_npubbytes();
size_t crypto_aead_aes256gcm_abytes();

int crypto_aead_aes256gcm_is_available();


int crypto_aead_aes256gcm_encrypt(unsigned char *c,
                                  unsigned long long *clen_p,
                                  const unsigned char *m,
                                  unsigned long long mlen,
                                  const unsigned char *ad,
                                  unsigned long long adlen,
                                  const unsigned char *nsec,
                                  const unsigned char *npub,
                                  const unsigned char *k);


int crypto_aead_aes256gcm_decrypt(unsigned char *m,
                                  unsigned long long *mlen_p,
                                  unsigned char *nsec,
                                  const unsigned char *c,
                                  unsigned long long clen,
                                  const unsigned char *ad,
                                  unsigned long long adlen,
                                  const unsigned char *npub,
                                  const unsigned char *k);
