#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include "plist.h"

void print(NODE *head) {

    NODE *cur = NULL;
    cur = head;

    printf("[");

    while (cur != NULL) {
        printf(" (%s:%s)\n ", (cur->p)->pname, (cur->p)->psecret);
        cur = cur->next;
    }
    printf("]");

}

bool exists(NODE *head, NODE *target) {
    printf("Check if the target node exists in list\n");

    NODE *cur = NULL;
    cur = head;
    while(cur != NULL)
        if((cur->p)->pname == (target->p)->pname)
            return 1;
    return 0;

}

NODE *get_node(NODE *head, char *pname) {

    NODE *cur = NULL;
    cur = head;
    while(cur != NULL) {
        if((cur->p)->pname == pname) {
            return cur;
        }
    }
    return NULL;
}

void push(NODE **head, char *pname, char *psecret) {

    NODE *cur = (NODE*) malloc(sizeof(NODE));

    PROVIDER *p = (PROVIDER*) malloc(sizeof(PROVIDER));
    p->pname = pname;
    p->psecret = psecret;
    cur->p = p;

    cur->next = *head;
    *head = cur;
    //printf("%s\n", (cur->p)->pname);
}

NODE *pop(NODE **head) {

    NODE *tmp = *head;
    *head = (*head)->next;
    return tmp;
}

void del(char *del, NODE *head) {

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
int main() {

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
