/***
 *
 *  TOTP: Time-Based One-Time Password Algorithm
 *  Copyright (c) 2017, fmount <fmount9@autistici.org>
 *
 *  Test Vector is composed by:
 *  key: ORSXG5A=
 *  msg: 1234
 *
 *  In order to test the hmac returned value from the openssl implementation
 *  check with bash launching:
 *
 *  $ echo -n "1234" | openssl dgst -sha1 -hmac "test"
 */

#include<unistd.h>

#include "rfc4226.h"
#include "rfc6238.h"

#include "../lib/utils.h"
#include "../lib/parser.h"

#define T0 0
#define DIGITS 6
#define VALIDITY 30


int totp(uint8_t *k, size_t keylen) {
    time_t t = floor((time(NULL) - T0) / VALIDITY);
    TOTP(k, keylen, t, DIGITS);
    return 0;
}

int main(int argc, char *argv[])
{

    size_t pos;
    size_t len;
    size_t keylen;
    uint8_t *k;
    char *fname = NULL;
    int opt;

    if(argc <= 1) {
        fprintf(stderr, "Provide at least one argument\n");
        return -1;
    }

    while((opt = getopt(argc, argv, "b:f:v")) != -1 ) {
        switch(opt) {
            case 'b':
                k = (uint8_t *)optarg;
                len = strlen(optarg);
                if (validate_b32key(optarg, len, pos) == 1) {
                    fprintf(stderr, "%s: invalid base32 secret\n", optarg);
                    return -1;
                }
                keylen = decode_b32key(&k, len);
                totp(k, keylen);
            case 'f':
                fname = optarg;
                load_providers(fname);
                print(provider_list);
                break;
            case 'v':
                break;
            default:
                fprintf(stderr, "Usage %s [-f fname] | [-b b32_secretkey] \n", argv[0]);
                return -1;
        }
    }
}
