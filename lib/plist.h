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

#ifndef PLIST_H
#define PLIST_H

#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<stdbool.h>


typedef struct {
    char *pname;
    char *psecret;
    uint32_t *otpvalue;
} PROVIDER;


typedef struct Node {
    PROVIDER *p;
    struct Node *next;
} NODE;


void print(NODE *head);
size_t size(NODE *head);
int update_value(NODE **head, char *pname, uint32_t optvalue);
void push(NODE **head, char *pname, char *psecret, uint32_t *otpvalue);
void del(char *del, NODE *head);
bool exists(NODE *head, NODE *target);
NODE *pop(NODE **head);
NODE *get_node(NODE *head, char *pname);

#endif
