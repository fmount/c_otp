#ifndef RFC6238_H
#define RFC6238_H

#include<stdlib.h>
#include<time.h>
#include "rfc4226.h"

#define TS 30	//time step in seconds, default value as per Google implementation


/******** RFC6238 **********
 *
 * TOTP = HOTP(k,T) where
 * K = the supersecret key
 * T = ( Current Unix time - T0) / X
 * where X is the Time Step
 *
 * *************************/


uint32_t TOTP(unsigned char* key, char* time, int tlen, int digits);

time_t get_time(time_t T0);

#endif
