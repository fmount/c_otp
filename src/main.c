/***
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
#include <time.h>
#include <signal.h>
#include <ctype.h>
#include "rfc4226.h"
#include "rfc6238.h"
#include "utils.h"
#include "parser.h"

#define T0 0
#define DIGITS 6
#define VALIDITY 30
#define TIME 2
#define VERSION 1.0

extern NODE *provider_list = NULL;

void
sig_handler(int sig)
{
    if (sig == SIGINT) {
        freeList(provider_list);
        exit(0);
    }
}

uint32_t
totp(uint8_t *k, size_t keylen)
{
    time_t t = floor((time(NULL) - T0) / VALIDITY);

    return TOTP(k, keylen, t, DIGITS);
}

uint32_t
accumulate(PROVIDER *cur_provider)
{

    size_t pos, len, keylen;
    uint8_t *k;
    uint32_t otp;

    len = strlen(cur_provider->psecret);
    char sec[len];

    strcpy(sec, cur_provider->psecret);

    k = (uint8_t *)&sec;

    if (validate_b32key(cur_provider->psecret, len, pos) == 1) {
        fprintf(stderr, "%s: invalid base32 secret\n", cur_provider->pname);
        return -1;
    }

    keylen = decode_b32key(&k, len);
    otp = totp(k, keylen);
    return otp;
}


void
update_providers(int time, int mode)
{

    NODE *cur = provider_list;
    NODE *head = provider_list;
    uint32_t result;

    signal(SIGINT, sig_handler);

    while (1) {
        while (cur != NULL) {
            result = accumulate(cur->p);
            update_value(&provider_list, (cur->p)->pname, result);
            cur = cur->next;
        }
        print(provider_list, mode);
        cur = head;
        sleep(TIME);
    }
}

void
usage(char *arg)
{
    fprintf(stderr, "Usage %s [-f fname] | [-b b32_secretkey] | [-m mode] [-s] | [-v]\n", arg);
}

int
main(int argc, char *argv[])
{

    size_t pos;
    size_t len;
    size_t keylen;
    uint8_t *k;
    char *fname = NULL;
    char *key;
    int mode = 0;
    int opt;
    uint32_t result;

    if (argc <= 1) {
        fprintf(stderr, "Provide at least one argument\n");
        return -1;
    }

    int sshot = 0;
    int update = 0;

    /* Processing cli parameters and make a few checks on the input */
    while ((opt = getopt(argc, argv, "b:f:m:vs")) != -1) {
        switch(opt) {
        case 'b':
            key = optarg;
            sshot = 1;
            break;
        case 'm':
            if (!isdigit(optarg[0])) {
                usage(argv[0]);
                return -1;
            }
            mode = atoi(optarg);
            break;
        case 'f':
            fname = optarg;
            break;
        case 's':
            update = 1;
            break;
        case 'v':
            printf("%s %.1f\n", argv[0], VERSION);
            return 0;
        default:
            usage(argv[0]);
            return -1;
        }
    }

    /* Single shot computing */
    if (sshot == 1) {
        len = strlen(key);
        if (validate_b32key(key, len, pos) == 1) {
            fprintf(stderr, "%s: invalid base32 secret\n", key);
            return -1;
        }
        k = (uint8_t *)key;
        keylen = decode_b32key(&k, len);
        result = totp(k, keylen);
        printf("The resulting OTP value is: %06u\n", result);
        return 0;
    }

    if (fname == NULL) {
        usage(argv[0]);
        return -1;
    }

    load_providers(fname);

    if (update == 1)
        update_providers(TIME, mode);
    else {
        NODE *cur = provider_list;
        uint32_t result;
        while (cur != NULL) {
            result = accumulate(cur->p);
            update_value(&provider_list, (cur->p)->pname, result);
            cur = cur->next;
        }
        print(provider_list, mode);
    }
    /* Free the provider list before exit
     * or blocks will be still reachable */
    freeList(provider_list);
}
