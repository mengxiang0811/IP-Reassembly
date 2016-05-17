#ifndef  IP_REASSEMBLE_H
#define  IP_REASSEMBLE_H

#include <netinet/in.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>


#include "dlist.h"
#include "checksum.h"


#define MAC_HDRLEN 14         /* The length of the MAC header  */
#define IP_HDRLEN  20         /* The length of the IP header  */
#define IPREASS_TIMEOUT 3000000    /* The time that uses for a IP group timeout */


//struct    ipacket *ip_defrag(struct ipacket *packet);
struct 		packet_data * _malloc_pdata(uint8_t *p_data,struct iphdr *ip);
void 		ipfrag_free(struct ip_frag * ipf);
void		ipq_free(struct ipq *qp);
uint8_t   	*ip_defrag(struct ipacket *packet);
void      	ip_frag_queue(struct ipq *qp, struct packet_data *packet,uint16_t offset,uint16_t len);
uint16_t  	que_length(struct ipq *qp);
uint8_t   	*ip_frag_reasm(struct ipq *qp,struct packet_data *packet);
void      	ipq_put(struct ipq *qp);
void      	ip_frag_init();
uint16_t        FRAG_LENGTH(struct iphdr *iph);
uint16_t        FRAG_OFFSET(struct iphdr *iph);

#endif
