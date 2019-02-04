/*
 *
 *  TOTP: Time-Based One-Time Password Algorithm
 *  Copyright (c) 2017, fmount <fmount@inventati.org>
 *
 *  This software is distributed under MIT License
 *
 *  Compute the hmac using openssl library.
 *  SHA-1 engine is used by default, but you can pass another one,
 *
 *  e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
 *
 */

#include "utils.h"

PROVIDER *split_str(char *spl, char delim)
{
    char *tmp_name;
    char *tmp_secret;
    PROVIDER *p;
    size_t count = 0;

    //Get break point
    do {
        count++;
    } while (spl[count] != delim);


    tmp_name = (char *) malloc(count * sizeof(char));
    tmp_secret = (char *) malloc((strlen(spl)-count) * sizeof(char));

    /*
     * Get first part of the string
     */
    memcpy(tmp_name, spl, count);
    /*
     * Get second part of the string
     */
    memcpy(tmp_secret, spl+(strlen(tmp_name)+1), (strlen(spl)-strlen(tmp_name))-2);

#ifdef DEBUG

    printf("[GOT LEN]: %ld\n", strlen(spl));
    printf("[PROVIDER SECTION]: %ld characters\n", count);
    printf("[GOT NAME]: %s\n", tmp_name);
    printf("[SECRET SECTION]: %ld\n", (strlen(spl)-count+1));
    printf("[GOT SECRET]: %s\n", tmp_secret);

#endif

    p = malloc(sizeof(PROVIDER));
    p->pname = tmp_name;
    p->psecret = tmp_secret;
    p->otpvalue = NULL;
    return p;
}


PROVIDER *process_provider(NODE **plist, char *line)
{
    PROVIDER *p;
    p = split_str(line, ':');
    push(plist, p->pname, p->psecret, p->otpvalue);
    return p;
}

static const int8_t base32_vals[256] = {
    //    This map cheats and interprets:
    //       - the numeral zero as the letter "O" as in oscar
    //       - the numeral one as the letter "L" as in lima
    //       - the numeral eight as the letter "B" as in bravo
    // 00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x00
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x10
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x20
    14, 11, 26, 27, 28, 29, 30, 31,  1, -1, -1, -1, -1,  0, -1, -1, // 0x30
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 0x40
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, // 0x50
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 0x60
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, -1, -1, -1, -1, // 0x70
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x80
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x90
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xA0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xB0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xC0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xD0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xE0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xF0
};


int 
validate_b32key(char *k, size_t len, size_t pos)
{

    // validates base32 key
    if (((len & 0xF) != 0) && ((len & 0xF) != 8))
        return 1;
    for (pos = 0; (pos < len); pos++) {
        if (base32_vals[k[pos]] == -1)
            return 1;
        if (k[pos] == '=') {
            if (((pos & 0xF) == 0) || ((pos & 0xF) == 8))
                return(1);
            if ((len - pos) > 6)
                return 1;
            switch (pos % 8) {
            case 2:
            case 4:
            case 5:
            case 7:
                break;
            default:
                return 1;
            }
            for ( ; (pos < len); pos++) {
                if (k[pos] != '=')
                    return 1;
            }
        }
    }
    return 0;
}


size_t
decode_b32key(uint8_t **k, size_t len)
{

    size_t keylen;
    size_t pos;
    // decodes base32 secret key
    keylen = 0;
    for (pos = 0; pos <= (len - 8); pos += 8) {
    // MSB is Most Significant Bits  (0x80 == 10000000 ~= MSB)
    // MB is middle bits             (0x7E == 01111110 ~= MB)
    // LSB is Least Significant Bits (0x01 == 00000001 ~= LSB)

    // byte 0
    (*k)[keylen+0]  = (base32_vals[(*k)[pos+0]] << 3) & 0xF8; // 5 MSB
    (*k)[keylen+0] |= (base32_vals[(*k)[pos+1]] >> 2) & 0x07; // 3 LSB
    if ((*k)[pos+2] == '=') {
        keylen += 1;
        break;
    }

    // byte 1
    (*k)[keylen+1]  = (base32_vals[(*k)[pos+1]] << 6) & 0xC0; // 2 MSB
    (*k)[keylen+1] |= (base32_vals[(*k)[pos+2]] << 1) & 0x3E; // 5  MB
    (*k)[keylen+1] |= (base32_vals[(*k)[pos+3]] >> 4) & 0x01; // 1 LSB
    if ((*k)[pos+4] == '=') {
        keylen += 2;
        break;
    }

    // byte 2
    (*k)[keylen+2]  = (base32_vals[(*k)[pos+3]] << 4) & 0xF0; // 4 MSB
    (*k)[keylen+2] |= (base32_vals[(*k)[pos+4]] >> 1) & 0x0F; // 4 LSB
    if ((*k)[pos+5] == '=') {
        keylen += 3;
        break;
    }

    // byte 3
    (*k)[keylen+3]  = (base32_vals[(*k)[pos+4]] << 7) & 0x80; // 1 MSB
    (*k)[keylen+3] |= (base32_vals[(*k)[pos+5]] << 2) & 0x7C; // 5  MB
    (*k)[keylen+3] |= (base32_vals[(*k)[pos+6]] >> 3) & 0x03; // 2 LSB
    if ((*k)[pos+7] == '=') {
        keylen += 4;
        break;
    }

    // byte 4
    (*k)[keylen+4]  = (base32_vals[(*k)[pos+6]] << 5) & 0xE0; // 3 MSB
    (*k)[keylen+4] |= (base32_vals[(*k)[pos+7]] >> 0) & 0x1F; // 5 LSB
    keylen += 5;
    }
    (*k)[keylen] = 0;

    return keylen;
}
