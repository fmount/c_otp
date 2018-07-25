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

#ifndef _UTILS_H
#define _UTILS_H

#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include<string.h>

int validate_b32key(char *k, size_t len, size_t pos);
size_t decode_b32key(uint8_t **k, size_t len);

#endif
