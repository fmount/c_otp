//#pragma once
#ifndef RFC4226_H
#define RFC4226_H

#include<stdint.h>
#include<stdlib.h>

//MAIN HOTP function
int HOTP(uint8_t *key, size_t kl, uint64_t interval, int digits);
//First step
uint8_t *hmac(unsigned char *key, int kl, uint64_t interval);
//Second step
uint32_t DT(uint8_t *digest);

#endif
