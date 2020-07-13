/* Copyright 2013-2018 Donald Stufft and individual contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

static const int PYNACL_HAS_CRYPTO_STREAM_XCHACHA20;

size_t crypto_stream_chacha20_keybytes();
size_t crypto_stream_chacha20_noncebytes();
size_t crypto_stream_chacha20_messagebytes_max();

size_t crypto_stream_chacha20_ietf_keybytes();
size_t crypto_stream_chacha20_ietf_noncebytes();
size_t crypto_stream_chacha20_ietf_messagebytes_max();

size_t crypto_stream_xchacha20_keybytes();
size_t crypto_stream_xchacha20_noncebytes();
size_t crypto_stream_xchacha20_messagebytes_max();

int crypto_stream_chacha20(unsigned char *c, unsigned long long clen,
                           const unsigned char *n, const unsigned char *k);

int crypto_stream_chacha20_xor(unsigned char *c, const unsigned char *m,
                               unsigned long long mlen, 
                               const unsigned char *n,
                               const unsigned char *k);

int crypto_stream_chacha20_xor_ic(unsigned char *c, const unsigned char *m,
                                  unsigned long long mlen,
                                  const unsigned char *n, uint64_t ic,
                                  const unsigned char *k);

void crypto_stream_chacha20_keygen(unsigned char *k);

int crypto_stream_chacha20_ietf(unsigned char *c, unsigned long long clen,
                                const unsigned char *n, 
                                const unsigned char *k);

int crypto_stream_chacha20_ietf_xor(unsigned char *c, const unsigned char *m,
                                    unsigned long long mlen, 
                                    const unsigned char *n,
                                    const unsigned char *k);

int crypto_stream_chacha20_ietf_xor_ic(unsigned char *c, 
                                       const unsigned char *m,
                                       unsigned long long mlen,
                                       const unsigned char *n, uint32_t ic,
                                       const unsigned char *k);

void crypto_stream_chacha20_ietf_keygen(unsigned char *k);

int crypto_stream_xchacha20(unsigned char *c, unsigned long long clen,
                            const unsigned char *n, const unsigned char *k);

int crypto_stream_xchacha20_xor(unsigned char *c, const unsigned char *m,
                                unsigned long long mlen,
                                const unsigned char *n,
                                const unsigned char *k);

int crypto_stream_xchacha20_xor_ic(unsigned char *c, const unsigned char *m,
                                   unsigned long long mlen,
                                   const unsigned char *n, uint64_t ic,
                                   const unsigned char *k);

void crypto_stream_xchacha20_keygen(unsigned char *k);
