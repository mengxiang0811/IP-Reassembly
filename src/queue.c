#include "queue.h"

struct node *create(const unsigned char *packet_content)
{
	struct node *n = (struct node *)malloc(sizeof(struct node));
	memset(n,0,sizeof(struct node));
	n->packet_content = (unsigned char *)packet_content;
	return n;
}

int isEmpty(struct queue *que)
{
	if (!que->head)
		return 1;
	return 0;
}

void push(struct queue *que,struct node *n)
{
	if (isEmpty(que))
		que->head = que->tail = n;
	else
	{
		que->tail->next = n;
		que->tail = n;
	}
}

struct node *pop(struct queue *que)
{
	if (isEmpty(que))
		return NULL;
	else if (que->head == que->tail)
	{
		struct node *tmp =  que->head;
		que->head = que->tail = NULL;
		return tmp;
	}
	else
	{
		struct node *tmp = que->head;
		que->head = que->head->next;
		return tmp;
	}
}

int element_number(struct queue *que)
{
	if (isEmpty(que))
		return 0;

	int counter = 0;
	struct node *cur = que->head;
	for (; cur; cur = cur->next)
		counter++;

	return counter;
}


