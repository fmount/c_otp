#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include<math.h>

#include "rfc6238.h"


time_t get_time(time_t t0){
	
	return floor((time(NULL) - t0) / TS);
}

uint32_t TOTP(unsigned char* key, char* time, int tlen, int digits){
	
	//unsigned char* totp;
	uint32_t totp;

	totp = HOTP(key, time, tlen, digits);

	return totp;
}
