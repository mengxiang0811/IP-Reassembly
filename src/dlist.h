/*
 *This file describes the base structure of the main data
 *which for accepting the ip fragment and processing the fragments
 *into one whole ip packet
 * 
 * Modified date: 2010/9/4
 *
 * */


#include <netinet/ip.h>
#include <pthread.h>
#include "packet.h"


#define ID_SIZE      65536   /* Size of different fragment IDs */
#define MAX_DATAGRAM 40      /* max size of the IP datagram number that in memory */

struct packet_data;/* struct of the packet data  */
struct ip_frag;  /* struct of ip fragment */
struct ipq;      /* struct of ip_pair queue */
struct queue_header;

struct packet_data
{
	uint8_t *p_nh;			 /* points to the IP header of the IP fragmentation */
	uint8_t *p_data;         /* points to the start address of the data of ipacket */
};

struct ip_frag
{
	struct ip_frag *next;      /* pointer that points to the next ip fragment */
	struct packet_data *packet;    /* pointer that points to the IP packet  */

	uint16_t frag_offset;      /* the fragment's offset  */
	uint16_t frag_end;         /* the last position of the fragment's data in original packet's data */
};

struct ipq
{
	struct ipq *next;          /* pointer of the next ip fragment queue  */
	struct ip_frag *ipfa_head; /* pointer of the head of the ip fragment queue  */
	struct iphdr ip_header;    /* the header of the IP packet? */
	uint16_t datagram_len;     /* the total length of the datagram  */
	uint64_t pqc_time;         /* the ip fragment queue creating time,for calculating the timeout */
};

struct queue_header
{
	uint16_t queue_number;
	struct ipq *next;
	pthread_mutex_t que_mtx;
};
