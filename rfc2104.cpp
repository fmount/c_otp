
#include<stdio.h>
#include<stdlib.h>

#include<c_totp/sha.h>


#define BLOCK_LEN = 64;
#define INNER_PAD = 0x36;
#define OUTER_PAD = 0x5C;




/*
 * calculate HMAC as per RFC2104
 * 
 * @which_sha: One of SHA1, SHA224, SHA384, SHA512
 * @key: HMAC hashing key; it needs to be
 * @keylen: the lenght of the secret shared key
 * @message: plaintext of the message you want to get the HMAC out of
 *
 * The main purpose is to calculate the following function based on RFC2104
 *
 *         H(key XOR OUTER_PAD, H(key XOR INNER_PAD, message))
 */


int HMAC(SHAversion which_sha, const unsigned char *plain_text,
		 const unsigned char *key, int kl, uint_8 digest[USHAMaxHashSize]){
 
 
	int i, blocksize, hashsize;
	blocksize = USHABlockSize(which_sha)

	int pad = blocksize - keylen

	if(kl > blocksize){
		printf("We need to pad\n");
	}

	//Now we can perform the first step of the function
	
	for(i = 0; i < kl, i++){
		k_ipad[i] = key[i] ^ INNER_PAD;
	}

	return -1
 
}
