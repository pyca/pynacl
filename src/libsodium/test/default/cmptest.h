
#ifndef __CMPTEST_H__
#define __CMPTEST_H__

#include <stdio.h>

#include "sodium.h"

#define TEST_NAME_RES TEST_NAME ".res"
#define TEST_NAME_OUT TEST_SRCDIR "/" TEST_NAME ".exp"

FILE *fp_res;
int   xmain(void);

int main(void)
{
    FILE *fp_out;
    int   c;

    if ((fp_res = fopen(TEST_NAME_RES, "w+")) == NULL) {
        perror("fopen(" TEST_NAME_RES ")");
        return 99;
    }
    if (sodium_init() != 0) {
        return 99;
    }
    xmain();
    rewind(fp_res);
    if ((fp_out = fopen(TEST_NAME_OUT, "r")) == NULL) {
        perror("fopen(" TEST_NAME_OUT ")");
        return 99;
    }
    do {
        if ((c = fgetc(fp_res)) != fgetc(fp_out)) {
            return 99;
        }
    } while (c != EOF);

    return 0;
}

#undef  printf
#define printf(...) fprintf(fp_res, __VA_ARGS__)
#define main xmain

#endif
