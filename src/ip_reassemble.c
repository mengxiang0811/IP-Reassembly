#include "ip_reassemble.h"

struct queue_header *FRAID;         /* global array for ip fragment queues  */

static uint32_t count = 0;
void ip_frag_init()
{
	FRAID = (struct queue_header *)malloc(sizeof(struct queue_header) * ID_SIZE);

	if (!FRAID)
	{
		printf("Init array FRAID error!exit\n");
		exit(-1);
	}

	int i = 0;
	for (; i < ID_SIZE; i++)
	{
		FRAID[i].queue_number = 0;
		pthread_mutex_init(&FRAID[i].que_mtx,NULL);
		FRAID[i].next = NULL;
	}
}

struct packet_data * _malloc_pdata(uint8_t *p_data,struct iphdr *ip)
{
	struct packet_data *pdata = (struct packet_data *)malloc(sizeof(struct packet_data));

	pdata->p_data = (uint8_t *)malloc(MAC_HDRLEN + ntohs(ip->tot_len));
	pdata->p_nh = (uint8_t *)malloc(sizeof(struct iphdr));

	memset(pdata->p_data,0,MAC_HDRLEN + ntohs(ip->tot_len));
	memset(pdata->p_nh,0,sizeof(struct iphdr));

	memcpy(pdata->p_data,p_data,(MAC_HDRLEN + ntohs(ip->tot_len)));
	memcpy(pdata->p_nh,ip,sizeof(struct iphdr));

	return pdata;
}

void ipfrag_free(struct ip_frag * ipf)
{
	ipf->next = NULL;

	if (ipf->packet->p_data)
		free(ipf->packet->p_data);
	if (ipf->packet->p_nh)
		free(ipf->packet->p_nh);

	free(ipf->packet);
	free(ipf);
}

void ipq_free(struct ipq *qp)
{
	qp->next = NULL;
	qp->ipfa_head = NULL;
	free(qp);
}

uint16_t FRAG_LENGTH(struct iphdr *iph)
{
	return (ntohs(iph->tot_len) - (ntohs(iph->ihl) << 2));
}
uint16_t FRAG_OFFSET(struct iphdr *iph)
{
	return ((ntohs(iph->frag_off) & IP_OFFMASK) << 3);
}

uint8_t *ip_defrag(struct ipacket *packet)
{
	count++;
	printf("This is the %dth packet!\n",count);
	 /* extract the IP header from the struct of ipacket  */
	struct iphdr *fraghdr =(struct iphdr*)packet->p_nh;
	
	int found = 0;

	uint16_t id , offset , data_len;
	uint8_t *data;

	 /* Get the IP fragment id for indexing */
	id = ntohs(fraghdr->id);

	 /* The offset of the IP fragment's data  */                         
	offset = (ntohs(fraghdr->frag_off) & 0x1FFF) << 3;
	
	//printf("tot_len = %d , header = %d\n",ntohs(fraghdr->tot_len),fraghdr->ihl<<2);

	 /* The data length of the IP fragment */
	data_len = ntohs(fraghdr->tot_len) - (fraghdr->ihl<< 2); 

	//printf("offset = %d ,data_len = %d\n",offset,data_len);
	
	/* To get the p_data of the packet */
	struct packet_data *pdata = _malloc_pdata(packet->p_data,fraghdr);
			//printf("OK1!\n");
	pthread_mutex_lock(&FRAID[id].que_mtx);
			//printf("OK!\n");
	/* Get the head of the queue that the ip fragment header queue in */
	struct queue_header qp_header = FRAID[id];
	
	if (!qp_header.next)
	{
		printf("The queue now is null.the id = %d\n",id);
	}
	
	struct ipq *qp_cur = NULL,*qp_prev = NULL;  
	
	/* traversing the queue list to find the proper queue  */	
	for ( qp_cur = qp_header.next; qp_cur != NULL; )      
	{
		//printf("Time diff = %d",(time(NULL) - qp_cur->pqc_time));
		/* If the IP group timeouts , free the queue list  */
		if ((time(NULL) - qp_cur->pqc_time) > IPREASS_TIMEOUT)  
		{
			 /* It's the first group  */
			if (qp_prev == NULL)                       
			{
				qp_prev = qp_cur;
				FRAID[id].next = qp_cur->next;
				qp_cur = qp_cur->next;
				ipq_put(qp_prev);
				qp_prev = NULL;

				 /* continue to find a proper group  */
				continue; 
			}
			else    /* It's not the first group  */
			{
				//printf("2\n");
				qp_prev->next = qp_cur->next;
				ipq_put(qp_cur);
				qp_cur = qp_prev->next;
				continue;
			}
		}
				
		/* Find the queue list that the fragment in */			
		if (qp_cur->ip_header.daddr == fraghdr->daddr	\
			&& qp_cur->ip_header.saddr == fraghdr->saddr	\
			&& qp_cur->ip_header.protocol == fraghdr->protocol)
		{
			//printf("Here found!\n");
			found = 1;
			break;
		}
		else  /* Not find,Go to the next queue */
		{
			//printf("Not find!\n");
			if (qp_prev)
				qp_prev = qp_prev->next;
			else
				qp_prev = qp_cur;
			qp_cur = qp_cur->next;
		}
	}

	//printf("Here is ok.!\n");
	/* In the queue list not find the group it's in  */
	if (!found)
	{
		qp_prev = NULL;

		/* create a new group  */
		qp_cur = (struct ipq*)malloc(sizeof(struct ipq));

		if ( !qp_cur )
		{
			goto EXIT;
		}

		memset(qp_cur,0,sizeof(struct ipq));

		qp_cur->next = FRAID[id].next;
		//qp_header = qp_cur;
		FRAID[id].next = qp_cur;
		qp_cur->pqc_time = time(NULL);

		/* copy the IP header for later matching  */
		memcpy(&(qp_cur->ip_header),fraghdr,IP_HDRLEN);
		
		//printf("The header len is %d.\n",ntohs(qp_cur->ip_header.tot_len));
	}
	else
	{
		/* the fragment is the first one and the head is not the first */
		if ( ((fraghdr->frag_off & IP_OFFMASK) == 0 )	\
			&& ((qp_cur->ip_header.frag_off & IP_OFFMASK) != 0))
		{
			memcpy(&qp_cur->ip_header,fraghdr,IP_HDRLEN);
		}
	}

	 /* the fragment is the last one  */
	if ((ntohs(fraghdr->frag_off) & IP_MF) == 0)
	{
		//printf("The last one packet!\n");
		qp_cur->datagram_len = offset + data_len;
	}

	/* Insert the packet into the current queue */
	ip_frag_queue(qp_cur,pdata,offset,data_len);

	/* Get the total length of the whole IP fragmentations in current queue */
	uint16_t length = que_length(qp_cur);
	
	//printf("the length is %d.\n",length);

	//printf("The whole length is %d.\n",qp_cur->datagram_len);

	/* check if the group is a whole one  */
	if (length == qp_cur->datagram_len)
	{
		/* reassemble the fragmentation list to a whole packet */

		data = ip_frag_reasm(qp_cur,pdata);
		
		if (qp_cur == FRAID[id].next)
		{
			FRAID[id].next = qp_cur->next;
		}
		if (data)
		{
			printf("Reassemble successfully.\n");
		}
		else
		{
			goto EXIT;
		}
		if (qp_cur && qp_prev)
		{
			qp_prev->next = qp_cur->next;
		}
		else if (qp_prev)
		{
			qp_prev->next = NULL;
		}
		
		/* release the current queue */
		ipq_put(qp_cur);
		//printf("last!\n");
	}
	else
		goto EXIT;
	
	pthread_mutex_unlock(&FRAID[id].que_mtx);
	return data;
EXIT:
	pthread_mutex_unlock(&FRAID[id].que_mtx);
	return NULL;
}


/*
 *when a packet comes , try to insert it into the queue list
 */

void ip_frag_queue(struct ipq *qp,struct packet_data *packet,uint16_t offset,uint16_t len)
{
	struct ip_frag *ipf_cur = NULL,*ipf_prev = NULL;
	struct ip_frag *ipf = (struct ip_frag*)malloc(sizeof(struct ip_frag));

	memset(ipf,0,sizeof(struct ip_frag));

	struct iphdr *ip = (struct iphdr *)packet->p_nh;

	ipf->packet = packet;
	ipf->frag_offset = offset;
	ipf->frag_end = offset + len;
	ipf->next = NULL;

	if (qp->ipfa_head == NULL)
	{
		qp->ipfa_head = ipf;
		return;
	}

	struct iphdr *ip_cur = NULL, *ip_prev = NULL;
	struct iphdr *_ip =  (struct iphdr *)ipf->packet->p_nh;

	ipf_prev = NULL;
	ipf_cur = qp->ipfa_head;
	while (ipf_cur)
	{
		ip_cur = (struct iphdr *)ipf_cur->packet->p_nh;

		if (ipf_prev)
		{
			ip_prev = (struct iphdr *)ipf_prev->packet->p_nh;
			if ((offset < FRAG_OFFSET(ip_cur)) && (offset > FRAG_OFFSET(ip_prev)))
			{
				ipf->next = ipf_cur;
				ipf_prev->next = ipf;
				break;
			}
		}
		else
		{
			if (offset < FRAG_OFFSET(ip_cur))
			{
				ipf->next = qp->ipfa_head;
				qp->ipfa_head = ipf;
				break;
			}
		}

		ipf_prev = ipf_cur;
		ipf_cur = ipf_cur->next;
	}

	if (!ipf_cur)
	{
		ipf_prev->next = ipf;
		ip_prev = (struct iphdr *)ipf_prev->packet->p_nh;
	}

	if (ipf_cur) {
		ip_cur = (struct iphdr *)(ipf_cur->packet->p_nh);
		if (ipf->frag_end > FRAG_OFFSET(ip_cur))
		{
			uint16_t modify = FRAG_OFFSET(ip_cur) - offset + IP_HDRLEN;
			ip->tot_len = htons(modify);
			struct iphdr *tmp_hdr = (struct iphdr *)(ipf->packet->p_data + MAC_HDRLEN);
			tmp_hdr->tot_len = htons(modify);
	
			ipf->frag_end = ipf->frag_offset + ntohs(tmp_hdr->tot_len) - IP_HDRLEN;
		}
	}
	
	if (ipf_prev) {
		ip_prev = (struct iphdr *)(ipf_prev->packet->p_nh);
		if ((FRAG_OFFSET(ip_prev) + FRAG_LENGTH(ip_prev)) > FRAG_OFFSET(_ip))
		{
			uint16_t modify = offset - FRAG_OFFSET(ip_prev) + IP_HDRLEN;
			ip_prev->tot_len = htons(modify);
			struct iphdr *tmp_hdr = (struct iphdr *)(ipf_prev->packet->p_data + MAC_HDRLEN);
			tmp_hdr->tot_len = htons(modify);

			ipf_prev->frag_end = ipf_prev->frag_offset + ntohs(tmp_hdr->tot_len) - IP_HDRLEN;
		}
	}

	return ;
}

/*
 *
 *To calculate the data length of the IP fragment list
 *
 * */

uint16_t que_length(struct ipq *qp)
{
	uint16_t length = 0;
	struct ip_frag *ipf_cur = qp->ipfa_head;
	struct iphdr *ip;
	for (length = 0; ipf_cur != NULL; ipf_cur = ipf_cur->next)
	{
		ip = (struct iphdr *)ipf_cur->packet->p_nh;
		length += ntohs(ip->tot_len) - IP_HDRLEN;
	}
	
	return length;
}


/*
 *
 *This function accomplishes the reassembling process that is the queue list pq
 *
 * */
//struct ipacket
uint8_t *ip_frag_reasm(struct ipq *qp,struct packet_data *packet)
{

	// for debug
	static int count = 0;
	count++;

	uint32_t size = qp->datagram_len +IP_HDRLEN + MAC_HDRLEN;

	//printf("In frag_reassem(),the datagram length is %d.\n",size);

	uint8_t *p_data = (uint8_t *)malloc(size);
	if (!p_data)
	{
		printf("Allocate p_data failed!exit.\n");
		exit(-1);
	}
	memset(p_data,0,size);

	uint8_t *tail = p_data;

	memcpy(tail,packet->p_data,MAC_HDRLEN);
	tail += MAC_HDRLEN;

	struct iphdr hdr;
	memset(&hdr,0,sizeof(struct iphdr));
	memcpy(&hdr,packet->p_nh,sizeof(struct iphdr));

	hdr.tot_len = htons(qp->datagram_len + IP_HDRLEN);
	hdr.check = 0;
	hdr.frag_off = 0;
	hdr.check = checksum_t((uint16_t *)&hdr,IP_HDRLEN/2);

	memcpy(tail, &hdr,sizeof(struct iphdr));
	tail += IP_HDRLEN;

	struct ip_frag *ipf_cur = qp->ipfa_head;
	uint16_t tmp = ipf_cur->frag_end - ipf_cur->frag_offset;
	memcpy(tail,(ipf_cur->packet->p_data + MAC_HDRLEN + IP_HDRLEN),tmp);
	ipf_cur = ipf_cur->next;
	tail += tmp;

	int len = 0;
	for (;ipf_cur != NULL;ipf_cur = ipf_cur->next)
	{
		uint8_t *begin = ipf_cur->packet->p_data;
		begin = begin + MAC_HDRLEN + IP_HDRLEN;
		len = ipf_cur->frag_end - ipf_cur->frag_offset;
		if (tail + len > p_data + size) {
			fprintf(stderr, "error: invalid write..., count = %d\n", count);
		}
		memcpy(tail, begin, len);
		tail += ipf_cur->frag_end - ipf_cur->frag_offset;
	}

	return ((uint8_t *)p_data);
}


/*
uint8_t *ip_frag_reasm(struct ipq *qp,struct packet_data *packet)
{

	//struct iphdr *ippp = (struct iphdr *)packet->p_nh;
	//printf("tot_len = %d,id = %d,frag_off = %d\n",ntohs(ippp->tot_len),ntohs(ippp->id),ntohs(ippps->frag_off));

	uint32_t size = qp->datagram_len +IP_HDRLEN + MAC_HDRLEN;

	//printf("In frag_reassem(),the datagram length is %d.\n",size);

	uint8_t *p_data = (uint8_t *)malloc(size);
	memset(p_data,0,size);
	uint8_t *tail = p_data;

	struct ip_frag *ipf_cur = qp->ipfa_head;

#if 0
	struct iphdr *iphdr = (struct iphdr *)malloc(sizeof(struct iphdr));

	if (!iphdr)
		return NULL;
	memset(iphdr,0,sizeof(struct iphdr));
	memcpy(iphdr,packet->p_nh,sizeof(struct iphdr));
	//printf("tot_len = %d,id = %d,frag_off = %d\n",ntohs(iphdr->tot_len),ntohs(iphdr->id),ntohs(iphdr->frag_off));
	iphdr->tot_len = htons(qp->datagram_len + IP_HDRLEN);
	iphdr->check = 0;
	iphdr->frag_off = 0;
	//iphdr->check = ip_chksum(iphdr,IP_HDRLEN/2);
	//iphdr->check = cksum(iphdr,sizeof(struct iphdr)/2);
	iphdr->check = checksum_t((uint16_t *)iphdr,IP_HDRLEN/2);
#endif

	memcpy(tail,packet->p_data,MAC_HDRLEN);
	tail += MAC_HDRLEN;

	memcpy(tail,packet->p_nh,sizeof(struct iphdr));
	tail += IP_HDRLEN;

	struct iphdr *iphdr = (struct iphdr *)tail;
	memset(iphdr,0,sizeof(struct iphdr));
	memcpy(iphdr, packet->p_nh, sizeof(struct iphdr));

	iphdr->tot_len = htons(qp->datagram_len + IP_HDRLEN);
	iphdr->check = 0;
	iphdr->frag_off = 0;
	iphdr->check = checksum_t((uint16_t *)iphdr,IP_HDRLEN/2);

	uint8_t tmp = ipf_cur->frag_end - ipf_cur->frag_offset;
	memcpy(tail,(ipf_cur->packet->p_data + MAC_HDRLEN + IP_HDRLEN),tmp);
	ipf_cur = ipf_cur->next;
	tail += tmp;

	for (;ipf_cur != NULL;ipf_cur = ipf_cur->next)
	{
		uint8_t *begin = ipf_cur->packet->p_data;
		begin = begin + MAC_HDRLEN + IP_HDRLEN;
		memcpy(tail,begin,ipf_cur->frag_end - ipf_cur->frag_offset);
		tail += ipf_cur->frag_end - ipf_cur->frag_offset;
	}

	// packet->p_data = p_data;

	return ((uint8_t *)p_data);
	//return packet;
}*/



/*
 *
 *This function frees the list that the queue ipq points to.
 *To use this function when the reassembling process ends or the queue list exising time is out.
 *
 * */
void ipq_put(struct ipq *qp)
{
	if (qp->ipfa_head)
	{
		struct ip_frag *ipf = qp->ipfa_head->next, *ipf_prev = qp->ipfa_head;
		for (; ipf != NULL; ipf_prev = ipf,ipf = ipf->next)
		{
			ipfrag_free(ipf_prev);
		}
		ipfrag_free(ipf_prev);
	}
	ipq_free(qp);
		//printf("Free qp!\n");
}
