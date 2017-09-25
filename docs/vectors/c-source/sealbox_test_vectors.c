/*
 * Copyright 2017 Donald Stufft and individual contributors
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
 * Test vector generator/checker for libsodium's box_seal APIs
 * to build in a unix-like environment, use a command line like
 * $ cc sealbox_test_vectors.c -I${IPATH} -L${LPATH} -lsodium -o sealbox_test_vectors
 * with IPATH and LPATH defined to respectively point to libsodium's include path
 * and to the directory containing the link library libsodium.a or libsodium.o
 *
 */
#include <stdio.h>
#include <string.h>
#include <sodium.h>

int checkone (char *hxsecret, char *hxpub, size_t ptlen, char *hxplaintext,
	      size_t crlen, char *hxencrypted) {

    int pklen = crypto_box_PUBLICKEYBYTES;
    int sklen = crypto_box_SECRETKEYBYTES;

    char *skr = sodium_malloc (sklen);
    char *pub = sodium_malloc (pklen);
    char *txt = sodium_malloc (ptlen);
    char *crpt = sodium_malloc (crlen);
    char *outp = sodium_malloc (ptlen);

    int rs = sodium_hex2bin (skr, sklen, hxsecret, 2 * sklen,
                             NULL, NULL, NULL);
    rs |= sodium_hex2bin (pub, pklen, hxpub, 2 * pklen, NULL, NULL, NULL);
    rs |= sodium_hex2bin (txt, ptlen, hxplaintext, strlen (hxplaintext),
                          NULL, NULL, NULL);
    rs |= sodium_hex2bin (crpt, crlen, hxencrypted, strlen (hxencrypted),
                          NULL, NULL, NULL);

    if (rs == 0)
        rs = crypto_box_seal_open (outp, crpt, crlen, pub, skr);
    if (rs == 0)
        rs = sodium_memcmp (outp, txt, ptlen);

    sodium_free (crpt);
    sodium_free (txt);
    sodium_free (skr);
    sodium_free (pub);

    return rs;
}

void gentestline (int minmsglen, int maxmsglen) {

    int pklen = crypto_box_PUBLICKEYBYTES;
    int sklen = crypto_box_SECRETKEYBYTES;
    size_t txtlen = minmsglen + randombytes_uniform (maxmsglen - minmsglen + 1);
    size_t encrlen = txtlen + crypto_box_SEALBYTES;

    char *skr = sodium_malloc (sklen);
    char *pub = sodium_malloc (pklen);
    char *txt = sodium_malloc (txtlen);
    char *crpt = sodium_malloc (encrlen);

    crypto_box_keypair (pub, skr);
    randombytes_buf (txt, txtlen);

    crypto_box_seal (crpt, txt, txtlen, pub);

    char *hskr = sodium_malloc (sklen * 2 + 1);
    char *hpub = sodium_malloc (pklen * 2 + 1);
    char *htxt = sodium_malloc (txtlen * 2 + 1);
    char *hkrp = sodium_malloc (encrlen * 2 + 1);

    sodium_bin2hex (hskr, sklen * 2 + 1, skr, sklen);
    sodium_bin2hex (hpub, pklen * 2 + 1, pub, pklen);
    sodium_bin2hex (htxt, txtlen * 2 + 1, txt, txtlen);
    sodium_bin2hex (hkrp, encrlen * 2 + 1, crpt, encrlen);

    printf ("%s\t%s\t%zu:%s\t%zu:%s\n", hskr, hpub, txtlen, htxt, encrlen, hkrp);
}

int main (int argc, char **argv) {
/*
 * If called without any argument, the resulting executable will
 * read and hex decode the secret and public part of the receiver key,
 * the original plaintext and the ciphertext, and then
 * check if the message resulting from decrypting ciphertext with
 * the secret key is equal to the given plaintext
 *
 * If called with a sequence of integer arguments, sealbox_test_vectors
 * will generate the requested number of reference lines, encrypting 
 * random messages.
 *
 */
    if (sodium_init () == -1) {
        exit (1);
    }

    if (argc == 1) {
        size_t lsz = 0;
        char *line = NULL;
        ssize_t lln = 0;
        int res;
        char hxsecret[2 * crypto_box_SECRETKEYBYTES + 1];
        char hxpub[2 * crypto_box_PUBLICKEYBYTES + 1];
        char hxplaintext[2048 + 1];
        char hxencrypted[2048 + 2 * crypto_box_SEALBYTES + 1];
        char cmpplaintext[5 + 2048 + 1];
        char cmpencrypted[5 + 2048 + 2 * crypto_box_SEALBYTES + 1];
        size_t ptlen = 0;
        size_t crlen = 0;

        while (lln = getline (&line, &lsz, stdin) > 0) {
            if (lln > 0) {
                if (strncmp (line, "#", 1) == 0 ||
                        strncmp (line, "\n", 1) == 0 ||
                        strncmp (line, "\r", 1) == 0)
                    continue;

                sscanf (line, "%s%s%s%s",
                        hxsecret, hxpub, cmpplaintext, cmpencrypted);
                sscanf (cmpplaintext, "%zu:%s",
                        &ptlen, hxplaintext);
                sscanf (cmpencrypted, "%zu:%s",
                        &crlen, hxencrypted);
                if (ptlen == 0)
                        memset(hxplaintext, 0, sizeof(hxplaintext));
                if (crlen == 0)
                        memset(hxencrypted, 0, sizeof(hxencrypted));
                res = checkone (hxsecret, hxpub, ptlen, hxplaintext, crlen, hxencrypted);
                char *rsstr = (res == 0) ? "OK" : "FAIL";
                printf ("%s\t%s\t%zu:%s\t%zu:%s\t%s\n",
                        hxsecret, hxpub, ptlen, hxplaintext, crlen, hxencrypted, rsstr);
            }
            free (line);
            line = NULL;
        }
    } else {
        int nlines = atoi (argv[1]);
        int minmsgl = 128;
        int maxmsgl = 128;
        if (argc == 3) {
            minmsgl = atoi (argv[2]);
            maxmsgl = atoi (argv[2]) * 2;
        } else if (argc == 4) {
            minmsgl = atoi (argv[2]);
            maxmsgl = atoi (argv[3]);
        }
        for (int i = 0; i < nlines; i++) {
            gentestline (minmsgl, maxmsgl);
        }
    }
}
