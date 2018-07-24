#ifndef PLIST_H
#define PLIST_H

#include<stdio.h>
#include<stdlib.h>
#include<stdbool.h>


typedef struct {
    char *pname;
    char *psecret;
} PROVIDER;


typedef struct Node {

    PROVIDER *p;
    struct Node *next;
} NODE;


void print(NODE *head);
void push(NODE **head, char *pname, char *psecret);
void del(char *del, NODE *head);
bool exists(NODE *head, NODE *target);
NODE *pop(NODE **head);
NODE *get_node(NODE *head, char *pname);

#endif
