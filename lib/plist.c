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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "plist.h"

void
print(NODE *head)
{

    NODE *cur = NULL;
    cur = head;

    printf("[");

    while (cur != NULL && (cur->p)->otpvalue != NULL) {
        printf(" (%s: %06u) ", (cur->p)->pname, (cur->p)->otpvalue);
        cur = cur->next;
    }
    printf("]\n");

}

size_t
size(NODE *head)
{

    size_t count = 0;
    NODE *cur = NULL;
    cur = head;

    while(cur != NULL) {
        count++;
        cur = cur->next;
    }

    return count;
}

bool
exists(NODE *head, NODE *target)
{
    printf("Check if the target node exists in list\n");

    NODE *cur = NULL;
    cur = head;
    while(cur != NULL) {
        if((cur->p)->pname == (target->p)->pname)
            return 1;
        cur = cur->next;
    }
    return 0;

}

NODE *
get_node(NODE *head, char *pname)
{

    NODE *cur = NULL;
    cur = head;
    while(cur != NULL) {
        if((cur->p)->pname == pname) {
            return cur;
        }
        cur = cur->next;
    }
    return NULL;
}

int
update_value(NODE **head, char *pname, uint32_t optvalue)
{
    NODE *cur;
    cur = *head;
    uint32_t *x = &optvalue;
    while(cur != NULL) {
        if((cur->p)->pname == pname) {
            (cur->p)->otpvalue = *x;
            return 0;
        }
        cur = cur->next;
    }
    return -1;
}

void
push(NODE **head, char *pname, char *psecret, uint32_t *otpvalue)
{

    NODE *cur = (NODE*) malloc(sizeof(NODE));

    PROVIDER *p = (PROVIDER*) malloc(sizeof(PROVIDER));
    p->pname = pname;
    p->psecret = psecret;
    p->otpvalue = otpvalue;
    cur->p = p;
    cur->next = *head;
    *head = cur;
}

NODE *
pop(NODE **head)
{

    NODE *tmp = *head;
    *head = (*head)->next;
    return tmp;
}

void
del(char *del, NODE *head)
{

    if(head == NULL) {
        fprintf(stderr, "No valid list, no head found\n");
    }

    NODE *cur = NULL;
    NODE *prev = NULL;

    cur = prev = head;

    while(cur != NULL && (strcmp((cur->p)->pname, del) != 0)) {
        prev = cur;
        cur = cur->next;
    }
    // Reached the end, should return ..
    if(cur == NULL) return;

    /* Found the pname in the list, free the node and 
     * modify the pointer to next
     */
    prev->next = cur->next;
    free(cur);
}

/** TESTING MAIN 
int
main()
{

    //NODE *head = (NODE*) malloc(sizeof(NODE));
    NODE *head = NULL;
    NODE *tmp = NULL

    //Insert providers
    pushHead(&head, "AMAZON", "jsdios90");
    pushHead(&head, "GOOGLE", "jsdios90");
    pushHead(&head, "PROTONMAIL", "jsdios90");


    * Testing POP 
    * tmp = pop(&head);
    * printf("[POP] => Got Node: (%s - %s)\n", (tmp->p)->pname, (tmp->p)->psecret);
    * tmp = pop(&head);
    * printf("[POP] => Got Node: (%s - %s)\n", (tmp->p)->pname, (tmp->p)->psecret);
    *

    *  Testing DELETE of a given NODE ..
    *
    *  deleteNode("GOOGLE", head);
    *  deleteNode("AMAZON", head);
    *  deleteNode("PROTONMAIL", head);
    *  deleteNode("TESTINGDELETE", head);
    *
    **/
/**
    printlist(head);
    return 0;
}
*/
