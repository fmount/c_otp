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

#ifndef RFC4226_H
#define RFC4226_H

#include<stdint.h>
#include<stdlib.h>

//MAIN HOTP function
uint32_t HOTP(uint8_t *key, size_t kl, uint64_t interval, int digits);
//First step
uint8_t *hmac(unsigned char *key, int kl, uint64_t interval);
//Second step
uint32_t DT(uint8_t *digest);

#endif
