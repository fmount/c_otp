#define _GNU_SOURCE
#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<string.h>
#include<unistd.h>
#include "plist.h"



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

#if DEBUG

    printf("[GOT LEN]: %d\n", strlen(spl));
    printf("[PROVIDER SECTION]: %d characters\n", count);
    printf("[GOT NAME]: %s\n", tmp_name);
    printf("[SECRET SECTION]: %d\n", (strlen(spl)-count+1));
    printf("[GOT SECRET]: %s\n", tmp_secret);

#endif

    p = malloc(sizeof(PROVIDER));
    p->pname = tmp_name;
    p->psecret = tmp_secret;

    return p;
}

PROVIDER *process_provider(NODE **plist, char *line)
{
    PROVIDER *p;
    p = split_str(line, ':');
	pushHead(plist, p->pname, p->psecret);
    /* printf("GOT PROVIDER %s with secret %s\n", p->pname, p->psecret); */
	return p;
}

int main(int argc, char **argv)
{

    FILE *f;
    size_t len = 1024;
    char *fname = NULL;
    int opt;
	NODE *provider_list = NULL;

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

	if (fname == NULL)
		exit(ENOENT);

    f = fopen(fname, "r");

    if (f == NULL)
        exit(ENOENT);

    char *line = NULL;

    while (getline(&line, &len, f) != -1) {
        if (line[0] != '#')
		/*	printf("Got a comment, ignore it\n");
        else
		*/
			process_provider(&provider_list, line);
	}

    free(line);

	printlist(&provider_list);
    exit(EXIT_SUCCESS);

    return 0;
}
