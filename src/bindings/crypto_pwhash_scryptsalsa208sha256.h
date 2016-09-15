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

int crypto_pwhash_scryptsalsa208sha256(unsigned char * const out,
                                        unsigned long long outlen,
                                        const char * const passwd,
                                        unsigned long long passwdlen,
                                        const unsigned char * const salt,
                                        unsigned long long opslimit,
                                        size_t memlimit);

/* #define crypto_pwhash_scryptsalsa208sha256_STRBYTES 102 */
int crypto_pwhash_scryptsalsa208sha256_str(char out[102],
                                            const char * const passwd,
                                            unsigned long long passwdlen,
                                            unsigned long long opslimit,
                                            size_t memlimit);

int crypto_pwhash_scryptsalsa208sha256_str_verify(const char str[102],
                                                   const char * const passwd,
                                                   unsigned long long passwdlen);

