/***
 *
 *  TOTP: Time-Based One-Time Password Algorithm
 *  Copyright (c) 2017, fmount <fmount@inventati.org>
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
#include <string.h>
#include "rfc4226.h"
#include "rfc6238.h"
#include "config.h"
#include "arg.h"
#include "utils.h"

#include "parser.h"

extern NODE *provider_list = NULL;

uint32_t
totp(uint8_t *k, size_t keylen) {
    time_t t = floor((time(NULL) - T0) / VALIDITY);
    return TOTP(k, keylen, t, DIGITS);
}

uint32_t
accumulate(PROVIDER *cur_provider) {

    /**
     * STRATEGY: Use a tmp variable to make computation
     * on the b32 sec of the current PROVIDER
     */
    size_t pos, len, keylen;
    uint8_t *k;
    uint32_t otp;
    char *sec = (char *) malloc(strlen(cur_provider->psecret) * sizeof(char));
    len = strlen(cur_provider->psecret);
    /* duplicate sec variable locally: using strndup to avoid pointing on 
     * the same cell */
    sec = strndup(cur_provider->psecret, len);

    if (validate_b32key(sec, len, pos) == 1) {
        fprintf(stderr, "%s: invalid base32 secret\n", cur_provider->pname);
        return -1;
    }

    k = (uint8_t *)sec;
    keylen = decode_b32key(&k, len);
    otp = totp(k, keylen);
    return otp;
}

int
update_providers(int uc) {

    NODE *cur = provider_list;
    NODE *head = provider_list;
    uint32_t result;

    if(cur == NULL) {
        return -1;
    }

    /**
     * update value (uc) is 0, so we update values
     * one shot
     */
    if(uc == 0) {
        while(cur != NULL) {
            result = accumulate(cur->p);
            update_value(&provider_list, (cur->p)->pname, result);
            cur = cur->next;
        }
        print(provider_list);
        return 0;
    }


    while(uc) {
        while(cur != NULL) {
            result = accumulate(cur->p);

            //((int)result == -1) ? ((cur->p)->otpvalue = 0) : ((cur->p)->otpvalue = result);

            update_value(&provider_list, (cur->p)->pname, result);

            cur = cur->next;
        }
        print(provider_list);
        cur = head;
        sleep(TIME);
    }

    return 0;
}

static void
usage(char **argv)
{
    fprintf(stdout, "usage: %s [-f fname] [-m mode] [-z fingerprint] \n\
        %s [-b b32_secretkey] | [-v] | [-g fname] [-z fingerprint]\n", argv[0], argv[0]);
}

int
main(int argc, char *argv[])
{

    size_t pos;
    size_t len;
    size_t keylen;
    size_t lp = 0;
    uint8_t *k;
    char *fname = NULL;
    char *fingerprint = NULL;
    char *mode = NULL;
    int opt;
    int gen = 0; /* value defined to create an encrypted providerrc */
    int update = 0; /* 0 => will execute one shot calc, 1 => update in loop */
    uint32_t result;


    if(argc <= 1) {
        fprintf(stderr, "Provide at least one argument\n");
        return -1;
    }

    int long_index =0;
    while ((opt = getopt_long(argc, argv,"b:f:m:g:z:vsh",
                   long_options, &long_index )) != -1) {
        switch(opt) {
            case 'b':
                /**
                 * ONE SHOT MODE: pass the b32, run the algorithm and
                 * return the result!
                 */
                k = (uint8_t *)optarg;
                len = strlen(optarg);
                if (validate_b32key(optarg, len, pos) == 1) {
                    fprintf(stderr, "%s: invalid base32 secret\n", optarg);
                    return -1;
                }
                keylen = decode_b32key(&k, len);
                result = totp(k, keylen);
                fprintf(stdout, "The resulting OTP value is: %06u\n", result);
                return 0;
            case 'f':
                fname = optarg;
                if (file_exists(fname) != 0) {
                    fprintf(stderr, "%s: the provided file doesn't exists\n", fname);
                    return -1;
                }
                break;
            case 'g':
                fname = optarg;
                gen = 1;
                if (file_exists(fname) != 0) {
                    fprintf(stderr, "%s: the provided file doesn't exists\n", fname);
                    return -1;
                }
                break;
            case 'h':
                usage(argv);
                return 0;
            case 'm':
                mode = optarg;
                break;
            case 's':
                /* An attempt to make it integrated in a desktop environment:
                 * the idea is to set a TIME and display the new value 
                 * according to the TIME set (useful if running DE with
                 * i3status / i3block / slstatus on DWM)
                 */
                update = 1;
                break;
            case 'v':
                printf("%s %.1f", argv[0], VERSION);
                return 0;
            case 'z':
                fingerprint = optarg;
                break;
            default:
                usage(argv);
                exit(EXIT_FAILURE);
        }
    }

    if(gen == 1)
        return generate_encrypted_providers(fname, fingerprint);

    if(mode != NULL && (strcmp(mode, "gpg") == 0)) {
        /** Working in gpg mode, using gpgme provider **/
        lp = load_encrypted_providers(fname);

    } else {
        lp = load_providers(fname);
    }

    update_providers(update);
}
