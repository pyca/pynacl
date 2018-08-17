/*
 * Copyright 2018 Donald Stufft and individual contributors
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
 *
 * Test vector generator/checker for libsodium's crypto_secretstream APIs
 * to build in a unix-like environment, use a command line like
 * $ cc secretstream_test_vector.c \
 *     -I${IPATH} -L${LPATH} -lsodium \
 *     -o secretstream_test_vector
 * with IPATH and LPATH defined to respectively point to libsodium's include path
 * and to the directory containing the link library libsodium.a or libsodium.o
 *
 */
#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <unistd.h>

#define MAX_AD_SIZE 32
#define MAX_CHUNK_SIZE 512
#define CHK(cmd) \
    do { if ((rc = (cmd)) != 0) { \
        fprintf(stderr, "api call failed, code=%d", rc); \
        exit(1); \
    }} while(0)

int usage(int argc, char **argv) {
    fprintf(stderr, "Usage: %s [-c num_chunks] [-r]\n", argv[0]);
    return 1;
}

int main (int argc, char **argv) {
    int c, rc;
    int num_chunks = 1;
    int rekey = 0;

    crypto_secretstream_xchacha20poly1305_state state;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char m[MAX_CHUNK_SIZE];
    unsigned char ad[MAX_AD_SIZE];
    unsigned char ct[MAX_CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    char key_hex[sizeof(key) * 2 + 1];
    char header_hex[sizeof(header) * 2 + 1];
    char m_hex[sizeof(m) * 2 + 1];
    char ad_hex[sizeof(ad) * 2 + 1];
    char ct_hex[sizeof(ct) * 2 + 1];
    unsigned long long m_len, ad_len, ct_len;
    unsigned char tag;

    while ((c = getopt(argc, argv, "hc:r")) != -1) {
        switch (c) {
        case 'c':
            num_chunks = atoi(optarg);
            break;
        case 'r':
            rekey = 1;
            break;
        case 'h':
            return usage(argc, argv);
        default:
            return 1;
        }
    }
    if (optind < argc) return usage(argc, argv);

    if (sodium_init() == -1) {
        exit(1);
    }

    /* output format:
     * {
     *   "key": "hex",
     *   "header": "hex",
     *   "chunks": [
     *     {
     *       "tag": 0,
     *       "ad": "hex",
     *       "message": "hex",
     *       "ciphertext": "hex"
     *     },
     *     ...
     *   ]
     * }
     */

    crypto_secretstream_xchacha20poly1305_keygen(key);
    CHK(crypto_secretstream_xchacha20poly1305_init_push(&state, header, key));
    sodium_bin2hex(key_hex, sizeof key_hex, key, sizeof key);
    sodium_bin2hex(header_hex, sizeof header_hex, header, sizeof header);
    printf("{\n  \"key\": \"%s\",\n  \"header\": \"%s\",\n  \"chunks\": [\n",
           key_hex, header_hex);
    for (c = 1 ; c <= num_chunks ; ++c) {
        tag =
            c == num_chunks ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
            : rekey ? crypto_secretstream_xchacha20poly1305_TAG_REKEY
            : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
        ad_len = randombytes_uniform(MAX_AD_SIZE);
        m_len = randombytes_uniform(MAX_CHUNK_SIZE - 1) + 1;
        randombytes_buf(m, m_len);
        randombytes_buf(ad, ad_len);
        CHK(crypto_secretstream_xchacha20poly1305_push(
            &state, ct, &ct_len, m, m_len, ad, ad_len, tag));
        sodium_bin2hex(m_hex, m_len * 2 + 1, m, m_len);
        if (ad_len > 0) {
            sodium_bin2hex(ad_hex, ad_len * 2 + 1, ad, ad_len);
        }
        sodium_bin2hex(ct_hex, ct_len * 2 + 1, ct, ct_len);
        printf("    {\n"
               "      \"tag\": %d,\n      \"ad\": %s%s%s,\n"
               "      \"message\": \"%s\",\n      \"ciphertext\": \"%s\"\n"
               "    }%s\n",
               tag,
               ad_len > 0 ? "\"" : "",
               ad_len > 0 ? ad_hex : "null",
               ad_len > 0 ? "\"" : "",
               m_hex,
               ct_hex,
               c < num_chunks ? "," : "");
    }
    printf("  ]\n}\n");

    return 0;
}
