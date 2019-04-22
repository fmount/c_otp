/*
 *
 *  TOTP: Time-Based One-Time Password Algorithm
 *  Copyright (c) 2017, fmount <fmount9@autistici.org>
 *
 *  This software is distributed under MIT License
 *
 *  Compute the hmac using openssl library.
 *  SHA-1 engine is used by default, but you can pass another one,
 *
 *  e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
 *
 */

#ifndef RFC6238_H
#define RFC6238_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

#include "rfc4226.h"

#define TS 30   //time step in seconds, default value as per Google implementation


/******** RFC6238 **********
 *
 * TOTP = HOTP(k,T) where
 * K = the supersecret key
 * T = ( Current Unix time - T0) / X
 * where X is the Time Step
 *
 * *************************/


uint32_t TOTP(uint8_t *key, size_t kl, uint64_t time, int digits);
time_t get_time(time_t T0);

#endif
