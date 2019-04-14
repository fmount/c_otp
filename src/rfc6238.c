/*
 *
 *  TOTP: Time-Based One-Time Password Algorithm
 *  Copyright (c) 2017, fmount <fmount@inventati.org>
 *
 *  This software is distributed under MIT License
 *
 *  Compute the hmac using openssl library.
 *  SHA-1 engine is used by default, but you can pass another one,
 *
 *  e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
 *
 */

#include "rfc6238.h"


time_t
get_time(time_t t0)
{

    return floor((time(NULL) - t0) / TS);
}

uint32_t
TOTP(uint8_t *key, size_t kl, uint64_t time, int digits)
{

    uint32_t totp;
    totp = HOTP(key, kl, time, digits);
    return totp;
}
