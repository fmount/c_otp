#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include "plist.h"


void printlist(NODE **head) {

	NODE *cur = *head;
	
	printf("[ ");
	
	while (cur != NULL) {
		printf(" (%s:%s) ", (cur->p)->pname, (cur->p)->psecret);
		cur = cur->next;
	}
	printf(" ]");

}


void pushHead(NODE **head, char *pname, char *psecret) {
	
	NODE *cur = (NODE*) malloc(sizeof(NODE));
	
	PROVIDER *p = (PROVIDER*) malloc(sizeof(PROVIDER));
	p->pname = pname;
	p->psecret = psecret;
	cur->p = p;
	
	/**
	 * I am actually on head, return just the new node
	 */
	cur->next = *head;
	*head = cur;
	//printf("%s\n", (cur->p)->pname);
}

NODE *pop(NODE *head) {

	NODE *tmp = head;
	head = head->next;
	return tmp;
}

void deleteNode(char *del, NODE *head) {

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

/****
int main() {

	//NODE *head = (NODE*) malloc(sizeof(NODE));
	NODE *head = NULL;

	//Insert providers
	pushHead(&head, "AMAZON", "jsdios90");
	pushHead(&head, "GOOGLE", "jsdios90");
	pushHead(&head, "PROTONMAIL", "jsdios90");

	printlist(&head);
	return 0;
}
*****/
