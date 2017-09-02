/***
 *
 *  TOTP: Time-Based One-Time Password Algorithm
 *  Copyright (c) 2017, fmount <francesco.pan001@gmail.com>
 *
 *  Test Vector is composed by:
 *  key: ORSXG5A=
 *  msg: 1234
 *
 *  In order to test the hmac returned value from the openssl implementation
 *  check with bash launching:
 *
 *	$ echo -n "1234" | openssl dgst -sha1 -hmac "test"
 */


#include "utils.h"
#include "rfc4226.h"
#include "rfc6238.h"

int main(int argc, char * argv[]){

	size_t pos;
	size_t len;
	size_t keylen;
	uint8_t *k;

	switch(argc){
		case 2: 
			k  = (uint8_t *)argv[1];
			break;

		default:
			fprintf(stderr, "Usage: %s [b32_secretkey] \n", argv[0]);
			return(1);
			break;
	};

	//Get the len of the key passed as parameter..
	len = strlen(argv[1]);

	if(validate_b32key(argv[1], len, pos) == 1){
		fprintf(stderr, "%s: invalid base32 secret\n", argv[1]);
		exit(-1);
	}

	keylen = decode_b32key(&k,len);


	/*******
	 * TEST VECTOR
	 uint64_t t = 1234;
	 int digits = 6;
	 HOTP(k, keylen, t, digits);
	 ********/

	int digits = 6;
	time_t t0 = 0;
	time_t t = floor((time(NULL) - t0) / 30);
	
	//TOTP(k, keylen, (char *)&t, digits);
	TOTP(k, keylen, t, digits);
	

	return 0;
}
