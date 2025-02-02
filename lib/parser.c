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

#define MAX_LEN 256

PROVIDER
split_str(char *spl, char delim)
{
    char *tmp_name;
    char *tmp_secret;
    size_t count = 0;
    PROVIDER p;

    // Initialize an empty PROVIDER
    p = (PROVIDER) {
        .pname = NULL,
        .psecret = NULL,
        .otpvalue = -1,
    };

    if (!spl) {
        return p;
    }

    // Remove newline and temination from the string size
    //size_t totlen = strlen(spl) -2;
    size_t totlen = strlen(spl)-1; // remove \0

    if (totlen > MAX_LEN || totlen <= 3) {
        return p;
    }

    // Get break point
    do {
        count++;
    } while (spl[count] != delim && (count < totlen));

    // we reached the end of the string w/o finding a delimiter
    // this means this is not a malformed PROVIDER line, returning!
    if (count == totlen) {
        return p;
    }

    tmp_name = (char *) malloc(count * sizeof(char) + 1);
    if (!tmp_name) {
        free(tmp_name);
        return p;
    }
    //
    // remove delim char from the allocation space
    size_t slen = totlen - 1;
    tmp_secret = (char *) malloc((slen-count) * sizeof(char) + 1);
    if (!tmp_secret) {
        free(tmp_name);
        return p;
    }

    // Get first part of the string
    memcpy(tmp_name, spl, count);
    tmp_name[count] = '\0';
    // Get second part of the string
    memcpy(tmp_secret, spl+(count+1), (slen-count));
    tmp_secret[(slen-count)] = '\0';

#ifdef DEBUG
    printf("[GOT LEN]: %ld\n", strlen(spl));
    printf("[PROVIDER SECTION]: %ld characters\n", count);
    printf("[GOT NAME]: %s\n", tmp_name);
    printf("[SECRET SECTION]: %ld\n", (strlen(spl)-count+1));
    printf("[GOT SECRET]: %s\n", tmp_secret);
#endif

    p.pname = tmp_name;
    p.psecret = tmp_secret;

    return p;
}

void
process_provider(NODE **plist, char *line)
{
    PROVIDER p;
    p = split_str(line, ':');
    if (p.pname != NULL && p.psecret != NULL) {
        push(plist, p.pname, p.psecret, p.otpvalue);
    }
}

void
load_providers(char *fname)
{
    FILE *f;
    size_t len = 1024;

    if (fname == NULL)
        exit(ENOENT);

    f = fopen(fname, "r");
    if (f == NULL) {
        fprintf(stderr, "can't open %s: %s\n", fname, strerror(errno));
        exit(ENOENT);
    }
    char *line = NULL;
    while (getline(&line, &len, f) != -1) {
        if (line[0] != '#')
            process_provider(&provider_list, line);
    }
    free(line);
    fclose(f);
}

/*
int
main(int argc, char **argv)
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
}
*/
