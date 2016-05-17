#ifndef QUEUE_H__
#define QUEUE_H__

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

struct node
{
	unsigned char *packet_content;
	struct node *next;
};

struct queue
{
	struct node *head;
	struct node *tail;
//	pthread_mutex_t pq_mtx;
};

struct node *create(const unsigned char *packet_content);
void push(struct queue *que,struct node *n);
struct node * pop(struct queue *que);
int isEmpty(struct queue *que);
int element_number(struct queue *que);
#endif
