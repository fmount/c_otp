#define _GNU_SOURCE
#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<string.h>
#include<unistd.h>

#include "plist.h"


static NODE *provider_list = NULL;

PROVIDER *split_str(char *spl, char delim);
PROVIDER *process_provider(NODE **plist, char *line);
void load_providers(char *fname);
