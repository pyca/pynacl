/* Copyright 2021 Donald Stufft and individual contributors
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

#ifdef SODIUM_LIBRARY_MINIMAL
static const int PYNACL_HAS_CRYPTO_SCALARMULT_RISTRETTO25519 = 0;

size_t (*crypto_scalarmult_ristretto255_bytes)(void) = NULL;
size_t (*crypto_scalarmult_ristretto255_scalarbytes)(void) = NULL;

int (*crypto_scalarmult_ristretto255_base)(unsigned char *q, const unsigned char *n) = NULL;
int (*crypto_scalarmult_ristretto255)(unsigned char *q, const unsigned char *n, const unsigned char *p) = NULL;
#else
static const int PYNACL_HAS_CRYPTO_SCALARMULT_RISTRETTO25519 = 1;
#endif
