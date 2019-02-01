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

#ifndef _GPGMELIB_H
#define _GPGMELIB_H

#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include<gpgme.h>

#define BUFSIZE 1024
#define MAXLEN 2048

void init_context(void);
void exit_with_err(gpgme_error_t err);
void print_keylist(gpgme_ctx_t ctx, gpgme_key_t key);
void select_key(gpgme_ctx_t ctx, char *fingerprint, gpgme_key_t *key);
void print_key_info(gpgme_key_t key);
int encrypt(char *fout, gpgme_ctx_t ctx, gpgme_key_t key[], \
     gpgme_data_t in, gpgme_data_t out, gpgme_encrypt_flags_t flags);
char *decrypt(char *fin, gpgme_ctx_t ctx, \
        gpgme_data_t in, gpgme_data_t out);
void write_file(char *fout, char *cipher_text, size_t bflen);
char *read_file(char *fin);
void print_gpgme_data(gpgme_data_t data);

#endif
