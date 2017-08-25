#include<stdio.h>
#include<stdlib.h>
#include<time.h>
//#include <cstdint>
#include "rfc6238.h"


unsigned char* TOTP(char* key, char* time, int tlen, int digits){
	
	unsigned char* totp;

	totp = HOTP(key, time, tlen, digits);

	return totp;
}
