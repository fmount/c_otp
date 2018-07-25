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

#define _GNU_SOURCE
#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<string.h>
#include<unistd.h>

#include "plist.h"
#include "parser.h"


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
    /* printf("GOT PROVIDER %s with secret %s\n", p->pname, p->psecret); */
    return p;
}

void load_providers(char *fname)
{

    FILE *f;
    size_t len = 1024;

    if (fname == NULL)
        exit(ENOENT);
    f = fopen(fname, "r");
    if (f == NULL)
        exit(ENOENT);
    char *line = NULL;
    while (getline(&line, &len, f) != -1) {
        if (line[0] != '#')
            process_provider(&provider_list, line);
    }

    free(line);

    #ifdef DEBUG

    print(provider_list);

    #endif
}

/*int main(int argc, char **argv)
{

    char *fname = NULL;
    int opt;
    if(argc <= 1) {
        fprintf(stderr, "Provide at least one argument\n");
        return -1;
    }

    while((opt = getopt(argc, argv, "f:v")) != -1 ) {
        switch(opt) {
            case 'f':
              fname = optarg;
              break;
            case 'v':
              break;
            default:
              fprintf(stderr, "Usage: %s [-f fname]\n", argv[0]);
        }
    }

    load_providers(fname);
    return 0;
}*/
