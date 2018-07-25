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
#include <time.h>
#include "rfc4226.h"
#include "rfc6238.h"
#include "utils.h"
#include "parser.h"

#define T0 0
#define DIGITS 6
#define VALIDITY 30
#define TIME 2

extern NODE *provider_list = NULL;

uint32_t totp(uint8_t *k, size_t keylen) {
    time_t t = floor((time(NULL) - T0) / VALIDITY);
    return TOTP(k, keylen, t, DIGITS);
}

uint32_t accumulate(PROVIDER *cur_provider) {

    size_t pos, len, keylen;
    uint8_t *k;
    uint32_t otp;
    char *sec = (char *)malloc(sizeof(char));

    memcpy(sec,cur_provider->psecret, strlen(cur_provider->psecret));
    k = (uint8_t *)cur_provider->psecret;
    len = strlen(cur_provider->psecret);

    if (validate_b32key(cur_provider->psecret, len, pos) == 1) {
        fprintf(stderr, "%s: invalid base32 secret\n", cur_provider->pname);
        return -1;
    }

    keylen = decode_b32key(&k, len);
    otp = totp(k, keylen);
    memcpy(cur_provider->psecret, sec, strlen(sec));
    printf("The resulting OTP value is: %06u\n", otp);
    return otp;
}

int main(int argc, char *argv[])
{

    size_t pos;
    size_t len;
    size_t keylen;
    uint8_t *k;
    char *fname = NULL;
    int opt;
    uint32_t result;

    if(argc <= 2) {
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
                break;
            case 'v':
                break;
            default:
                fprintf(stderr, "Usage %s [-f fname] | [-b b32_secretkey] \n", argv[0]);
                return -1;
        }
    }
    NODE *cur = provider_list;
    NODE *head = provider_list;

    while(1) {
        while(cur != NULL) {
            result = accumulate(cur->p);
            printf("The resulting OTP value is: %06u\n", result);
            //((int)result == -1) ? ((cur->p)->otpvalue = 0) : ((cur->p)->otpvalue = result);
            //(cur->p)->otpvalue = *result;
            update_value(&provider_list, (cur->p)->pname, result);
            print(provider_list);
            sleep(TIME);
            cur = cur->next;
        }
        print(provider_list);
        cur = head;
        sleep(5);
    }
}
