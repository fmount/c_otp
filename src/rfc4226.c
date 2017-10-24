/*
 *
 *  TOTP: Time-Based One-Time Password Algorithm
 *  Copyright (c) 2017, fmount <fmount9@autistici.org>
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
#include<string.h>
#include<math.h>
#include<openssl/hmac.h>
#include <openssl/evp.h>

#include "rfc4226.h"



uint8_t *hmac(unsigned char *key, int kl, uint64_t interval)
{

	return (uint8_t *)HMAC(EVP_sha1(), key, kl,
			(const unsigned char *)&interval, sizeof(interval), NULL, 0);
}

uint32_t DT(uint8_t *digest)
{

	uint64_t offset;
	uint32_t bin_code;

#if DEBUG

	char mdString[20];

	for (int i = 0; i < 20; i++)
		sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

	printf("HMAC digest: %s\n", mdString);

#endif

	// dynamically truncates hash
	offset   = digest[19] & 0x0f;

	bin_code = (digest[offset]  & 0x7f) << 24
		| (digest[offset+1] & 0xff) << 16
		| (digest[offset+2] & 0xff) <<  8
		| (digest[offset+3] & 0xff);

	// truncates code to 6 digits
#if DEBUG
	printf("OFFSET: %d\n", offset);
	printf("\nDBC1: %d\n", bin_code);
#endif

	return bin_code;

}


uint32_t mod_hotp(uint32_t bin_code, int digits)
{

	int power = pow(10, digits);
	uint32_t otp = bin_code % power;
#if DEBUG
	printf("\nPOWER: %d\n", power);
	printf("\nDBC2: %d\n", otp);
	//int len = snprintf (output_otp, digits + 1,
	//	"%.*ld", digits, mod_k(bin_code, power));
	//output_otp[digits] = '\0';
	//printf("OTP CODE: %s\n", output_otp);
#endif

	return otp;
}


int HOTP(uint8_t *key, size_t kl, uint64_t interval, int digits)
{

	uint8_t *digest;
	uint32_t result;
	uint32_t endianness;

#if DEBUG
	printf("KEY IS: %d\n", key);
	printf("KEY LEN IS: %d\n", kl);
	printf("COUNTER IS: %d\n", interval);
#endif


	endianness = 0xdeadbeef;
	if ((*(const uint8_t *)&endianness) == 0xef) {
		interval = ((interval & 0x00000000ffffffff) << 32) | ((interval & 0xffffffff00000000) >> 32);
		interval = ((interval & 0x0000ffff0000ffff) << 16) | ((interval & 0xffff0000ffff0000) >> 16);
		interval = ((interval & 0x00ff00ff00ff00ff) <<  8) | ((interval & 0xff00ff00ff00ff00) >>  8);
	};

	//First Phase, get the digest of the message using the provided key ...
	digest = (uint8_t *)hmac(key, kl, interval);
	//digest = (uint8_t *)HMAC(EVP_sha1(), key, kl, (const unsigned char *)&interval, sizeof(interval), NULL, 0);
	//Second Phase, get the dbc from the algotithm
	uint32_t dbc = DT(digest);

	//Third Phase: calculate the mod_k of the dbc to get the correct number
	result = mod_hotp(dbc, digits);
	//printf("OTP CODE: %s\n", result);

	printf("OTP VALUE IS: %06u\n", result);
	return 0;

}
