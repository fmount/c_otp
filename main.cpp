#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include "rfc4226.h"
#include "rfc6238.h"

int main(){

    // The key to hash
    char key[] = "012345678";
	int digits = 6;

	// The data that we're going to hash using HMAC
    char data[] = "hello world";


	//HOTP(key, data, digits);
	
	//uint64_t time = tc();
	time_t t0 = 0;
	time_t t = (time(NULL) - t0) / 30;
	//unsigned char* totp;
	
	//printf("Time is %d\n", time);

	TOTP(key, (char *)&t, sizeof(t), digits);
	//printf("totp: %06s\n", totp);
	return 0;
}
