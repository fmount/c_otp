#ifndef RFC6238_H
#define RFC6238_H

#include<stdlib.h>
#include<time.h>
#include<cstdint>
#include "rfc4226.h"

#define TS 30	//time step in seconds, default value as per Google implementation


/******** RFC6238 **********
 *
 * TOTP = HOTP(k,T)
 * T = ( Current Unix time - T0) / X
 *
 * TOTP(key, timestep, timebase, encode_base32, casefold)
 *
 */

unsigned char* TOTP(char* key, char* time, int tlen, int digits);

#endif
