#ifndef _UTILS_H
#define _UTILS_H

#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>


int validate_b32key(char *k, size_t len, size_t pos);

size_t decode_b32key(uint8_t **k, size_t len);

#endif
