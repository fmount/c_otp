#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<math.h>
#include<openssl/hmac.h>
#include "rfc4226.h"


/*
 * Compute the hmac using openssl library.
 * SHA-1 engine is used by default, but you can pass another one,
 * e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
 * TODO: pass dynamic method
 */
unsigned char* hmac(char *key, int kl, unsigned char* data, int dlen){
	
	return HMAC(EVP_sha1(), key, kl, data, dlen, NULL, NULL);

}


int DT(unsigned char *digest, int dlen){
	#if DEBUG

	char mdString[dlen];
    for(int i = 0; i < dlen; i++){
         sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
	}
	printf("HMAC digest: %s\n", mdString);
	printf("HMAC len: %d\n", dlen/2);
	
	#endif
	uint8_t offset = digest[dlen - 1] & 0x0f;
	
	int bin_code = (digest[offset]  & 0x7f) << 24 | (digest[offset+1] & 0xff) << 16
				    | (digest[offset+2] & 0xff) <<  8 | (digest[offset+3] & 0xff) ;

	#if DEBUG
	printf("OFFSET: %d\n", offset);
	printf("\nDBC1: %d\n", bin_code);
	#endif
	return bin_code;

}


unsigned char* mod_hotp(int bin_code, int digits){

	//char output_otp[digits + 1];
	unsigned char* output_otp;
	output_otp = (unsigned char*) malloc(sizeof(unsigned char*));
	#if DEBUG

	int power = pow(10,6);
	printf("\nPOWER: %d\n", power);
	printf("\nDBC2: %d\n", mod_k(bin_code,power));
	int len = snprintf (output_otp, digits + 1, "%.*ld", digits, mod_k(bin_code, power));
	output_otp[digits] = '\0';
	printf("OTP CODE: %s\n", output_otp);
    #endif

	return output_otp;	
}


unsigned char* HOTP(char *key, char *plaintext, int plen, int digits){

    unsigned char* digest;
	unsigned char* result;

	//First Phase, get the digest of the message using the provided key ...
	digest = hmac(key, strlen(key), (unsigned char*)plaintext, plen);

	//Second Phase, get the dbc from the algotithm
	size_t dlen = sizeof digest;
	int dbc = DT(digest, dlen);

	//Third Phase: calculate the mod_k of the dbc to get
	//the correct number
	result = mod_hotp(dbc, digits);
	printf("OTP CODE: %s\n", result);
	
	return result;

}

/* 
 *
 *
 * int main(){
    // The key to hash
    char key[] = "012345678";
	int digits = 6;
    // The data that we're going to hash using HMAC
    char data[] = "hello world";

    unsigned char* digest;

    // Using sha1 hash engine here.
    // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
    digest = HMAC(EVP_sha1(), key, strlen(key), (unsigned char*)data, strlen(data), NULL, NULL);    
 
    // Be careful of the length of string with the choosen hash engine. 
	// SHA1 produces a 20-byte hash value which rendered as 40 characters.
    // Change the length accordingly with your choosen hash engine
	#if DEBUG

	char mdString[20];
    for(int i = 0; i < 20; i++){
         sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
	}
	printf("HMAC digest: %s\n", mdString);
	printf("HMAC len: %d\n", strlen(mdString)/2);
	
	#endif
	uint8_t offset = digest[20 - 1] & 0x0f;
	
	int bin_code = (digest[offset]  & 0x7f) << 24 | (digest[offset+1] & 0xff) << 16
				    | (digest[offset+2] & 0xff) <<  8 | (digest[offset+3] & 0xff) ;

	#if DEBUG
	printf("OFFSET: %d\n", offset);
	printf("\nDBC1: %d\n", bin_code);

	int power = pow(10,6);
	printf("\nPOWER: %d\n", power);
	printf("\nDBC2: %d\n", mod_k(bin_code,power));
	char output_otp[digits + 1];
	int len = snprintf (output_otp, digits + 1, "%.*ld", digits, mod_k(bin_code, power));
	output_otp[digits] = '\0';
	printf("OTP CODE: %s\n", output_otp);
    #endif
	
	return 0;
}

***/
