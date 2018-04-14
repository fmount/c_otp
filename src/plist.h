#ifndef PLIST_H
#define PLIST_H

#include<stdio.h>
#include<stdlib.h>


typedef struct {
    char *pname;
    char *psecret;
} PROVIDER;


typedef struct Node {

	PROVIDER *p;
	struct Node *next;
} NODE;


void printlist(NODE **head);
void pushHead(NODE **head, char *pname, char *psecret);
NODE *pop(NODE *head);
void deleteNode(char *del, NODE *head);

#endif
