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

#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<string.h>
#include<unistd.h>

#include "plist.h"

//static NODE *provider_list = NULL;
//extern NODE *provider_list;

void load_providers(char *fname);
void load_encrypted_providers(char *fname, char *fingerprint);
