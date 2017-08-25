//#pragma once
#ifndef RFC4226_H
#define RFC4226_H
#define VALID_TOKEN 8
#define MASK 0x0f

#define mod_k(dbin_code, power) (dbin_code % power)

//MAIN HOTP function
unsigned char* HOTP(char *key, char *plaintext, int plen, int digits);
//First step
unsigned char* hmac(char *key, int kl, unsigned char* data, int dlen);
//Second step
int DT(unsigned char *hmac_hash, int len);
//Third and final step
unsigned char* mod_hotp(int bin_code, int digits);

#endif
