/* Copyright 2014 Donald Stufft and individual contributors
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


size_t crypto_pwhash_scryptsalsa208sha256_saltbytes(void);
size_t crypto_pwhash_scryptsalsa208sha256_strbytes(void);
size_t crypto_pwhash_scryptsalsa208sha256_bytes_min(void);
size_t crypto_pwhash_scryptsalsa208sha256_bytes_max(void);
size_t crypto_pwhash_scryptsalsa208sha256_passwd_min(void);
size_t crypto_pwhash_scryptsalsa208sha256_passwd_max(void);
size_t crypto_pwhash_scryptsalsa208sha256_opslimit_min(void);
size_t crypto_pwhash_scryptsalsa208sha256_opslimit_max(void);
size_t crypto_pwhash_scryptsalsa208sha256_memlimit_min(void);
size_t crypto_pwhash_scryptsalsa208sha256_memlimit_max(void);
size_t crypto_pwhash_scryptsalsa208sha256_opslimit_interactive(void);
size_t crypto_pwhash_scryptsalsa208sha256_memlimit_interactive(void);
size_t crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive(void);
size_t crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive(void);

int crypto_pwhash_scryptsalsa208sha256_ll(const uint8_t * const passwd,
                                           size_t passwdlen,
                                           const uint8_t * salt,
                                           size_t saltlen,
                                           uint64_t N, uint32_t r, uint32_t p,
                                           uint8_t * buf, size_t buflen);

/* #define crypto_pwhash_scryptsalsa208sha256_STRBYTES 102 */
int crypto_pwhash_scryptsalsa208sha256_str(char out[102],
                                            const char * const passwd,
                                            unsigned long long passwdlen,
                                            unsigned long long opslimit,
                                            size_t memlimit);

int crypto_pwhash_scryptsalsa208sha256_str_verify(const char str[102],
                                                   const char * const passwd,
                                                   unsigned long long passwdlen);

/*
 *  argon2i bindings
 */

size_t crypto_pwhash_argon2i_strbytes(void);
size_t crypto_pwhash_argon2i_saltbytes(void);
size_t crypto_pwhash_argon2i_bytes_min(void);
size_t crypto_pwhash_argon2i_bytes_max(void);
size_t crypto_pwhash_argon2i_passwd_min(void);
size_t crypto_pwhash_argon2i_passwd_max(void);
size_t crypto_pwhash_argon2i_memlimit_min(void);
size_t crypto_pwhash_argon2i_memlimit_max(void);
size_t crypto_pwhash_argon2i_memlimit_interactive(void);
size_t crypto_pwhash_argon2i_memlimit_moderate(void);
size_t crypto_pwhash_argon2i_memlimit_sensitive(void);
size_t crypto_pwhash_argon2i_opslimit_min(void);
size_t crypto_pwhash_argon2i_opslimit_max(void);
size_t crypto_pwhash_argon2i_opslimit_interactive(void);
size_t crypto_pwhash_argon2i_opslimit_moderate(void);
size_t crypto_pwhash_argon2i_opslimit_sensitive(void);
int crypto_pwhash_argon2i_alg_argon2i13(void);

int crypto_pwhash_argon2i(unsigned char * const out,
                          unsigned long long outlen,
                          const char * const passwd,
                          unsigned long long passwdlen,
                          const unsigned char * const salt,
                          unsigned long long opslimit, size_t memlimit,
                          int alg);

/* #define crypto_pwhash_argon2i_STRBYTES 128U */
int crypto_pwhash_argon2i_str(char out[128],
                              const char * const passwd,
                              unsigned long long passwdlen,
                              unsigned long long opslimit, size_t memlimit);

int crypto_pwhash_argon2i_str_verify(const char str[128],
                                     const char * const passwd,
                                     unsigned long long passwdlen);
