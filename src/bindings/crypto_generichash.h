/* Copyright 2013 Donald Stufft and individual contributors
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

// blake2b
size_t crypto_generichash_blake2b_bytes_min();
size_t crypto_generichash_blake2b_bytes_max();
size_t crypto_generichash_blake2b_bytes();

size_t crypto_generichash_blake2b_keybytes_min();
size_t crypto_generichash_blake2b_keybytes_max();
size_t crypto_generichash_blake2b_keybytes();
size_t crypto_generichash_blake2b_saltbytes();
size_t crypto_generichash_blake2b_personalbytes();

int crypto_generichash_blake2b_salt_personal(
				unsigned char *out, size_t outlen,
				const unsigned char *in,
				unsigned long long inlen,
				const unsigned char *key, size_t keylen,
				const unsigned char *salt,
				const unsigned char *personal);
