#include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "ip_reassemble.h"
#include "queue.h"

#define THREAD_NUM 1
#define SOURCE "input.pcap"
#define PATH "test2.pcap"

static int iii = 0;
static uint64_t pcounter = 0;
static int threadNumber = 0;
static struct queue *que;
pthread_mutex_t que_mtx;
pthread_t thr[THREAD_NUM];

struct ethhdr
{
	u_char h_source[6];
	u_char h_dest[6];
	uint16_t  h_proto;
};

struct pcap_pkthdr_t
{
	uint32_t ts_sec;
	uint32_t ts_usec;
	uint32_t caplen;
	uint32_t len;
};

FILE *out = NULL;

const char pfh[] = {
	0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00 
}; 

void print(uint8_t *pdata)
{
	struct in_addr s,d;
	struct iphdr *ipptr;
	ipptr=(struct iphdr *)(pdata+14);

	printf("\n-----IP Protocol (network layer)-----\n");
	printf("version: %d\n",ipptr->version);
	printf("header length: %d\n",ipptr->ihl*4);
	printf("tos: %d\n",ipptr->tos);
	printf("total length: %d\n",ntohs(ipptr->tot_len)); 
	printf("identification: %d\n",ntohs(ipptr->id));
	printf("DF: %d\n",(ntohs(ipptr->frag_off)&IP_DF) >> 14);
	printf("MF: %d\n",(ntohs(ipptr->frag_off)&IP_MF) >> 13);
	printf("offset: %d\n",(ntohs(ipptr->frag_off)&0x1fff)*8);
	printf("TTL: %d\n",ipptr->ttl);
	printf("checksum: %d\n",ntohs(ipptr->check));
	printf("protocol: %d\n",ipptr->protocol);
	s.s_addr=ipptr->saddr;
	d.s_addr=ipptr->daddr;
	printf("source address: %s\n",inet_ntoa(s));
	printf("destination address: %s\n",inet_ntoa(d));
	printf("\n");
}

 static pthread_mutex_t write_lock;

void pcap_init()
{
	int ret = 0;
	
	if (ret < 0)
	{
		fprintf(stderr,"Write to the pcap file error!\n");
		fclose(out);
		exit(-2);
	}
}

void write_to_pcap(uint8_t *data)
{
	struct pcap_pkthdr_t pkthdr;
	memset(&pkthdr,0,sizeof(struct pcap_pkthdr_t));

	struct timeval tv;
	gettimeofday(&tv, NULL);

	pkthdr.ts_sec = tv.tv_sec;
	pkthdr.ts_usec = tv.tv_usec;

	struct iphdr *ip = (struct iphdr *)(data + 14);
	uint16_t size = ntohs(ip->tot_len) + 14;

	pkthdr.caplen = size;
	pkthdr.len = size;

	fwrite(&pkthdr,sizeof(struct pcap_pkthdr_t),1,out);
	fwrite(data,size,1,out);
}

void *multi_func(void *arg)
{
	int i = *(int *)arg;
	printf("This is the %dth thread!\n",i);
	while(1){
		pthread_mutex_lock(&que_mtx);
		//printf("The elemenet number of the queue is %d.\n",element_number(que));
		struct node *n = pop(que);
		//printf("The elemenet number of the queue is %d.\n",element_number(que));
		//printf("This is the %dth packet!\n",iii);
		pthread_mutex_unlock(&que_mtx);

		if (n){

			printf("\nIn processing function!:Thread %d.\n",i);
			//print((uint8_t *)n->packet_content);
			struct ipacket *pdata = NULL;
			struct iphdr *ip = (struct iphdr *)(n->packet_content + MAC_HDRLEN);
			uint16_t len = ntohs(ip->tot_len) + MAC_HDRLEN;

			pdata = (struct ipacket *)malloc(sizeof(struct ipacket));
			memset(pdata,0,sizeof(struct ipacket));

			pdata->p_data = (uint8_t *)malloc(len);
			memcpy(pdata->p_data,n->packet_content,len);


			pdata->p_nh = (uint8_t *)malloc(sizeof(struct iphdr));
			memcpy(pdata->p_nh,ip,sizeof(struct iphdr));

			/*	pthread_mutex_lock(&write_lock);
				write_to_pcap((uint8_t *)pdata->p_data);
				pthread_mutex_unlock(&write_lock);*/

			uint8_t *data = NULL;
			data = ip_defrag(pdata);
	
			free(pdata->p_data);
			free(pdata->p_nh);
			free(pdata);

			if(data)
			{
				/*printf("------------------Packet after reassembled--------------------\n");
				struct ethhdr *ethptr;
				struct iphdr *ipptr;
				unsigned char *mac;
				ethptr=(struct ethhdr *)data;

				printf("\n----ethernet protocol(phydical layer)-----\n");
				printf("MAC source Address:\n");
				mac= (unsigned char *)ethptr->h_source;
				printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*mac,*(mac+1),*(mac+2),*(mac+3),*(mac+4),*(mac+5));
				printf("MAC destination Address:\n");
				mac= (unsigned char *)ethptr->h_dest;
				printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*mac,*(mac+1),*(mac+2),*(mac+3),*(mac+4),*(mac+5));
				printf("protocol:0x%04x\n",ntohs((uint16_t)ethptr->h_proto));
				printf("\n");
				print(data);*/
				
				pthread_mutex_lock(&write_lock);
				{
					struct pcap_pkthdr_t pkthdr;
					memset(&pkthdr,0,sizeof(struct pcap_pkthdr_t));
				
					struct timeval tv;
					gettimeofday(&tv, NULL);
				
					pkthdr.ts_sec = tv.tv_sec;
					pkthdr.ts_usec = tv.tv_usec;
				
					struct iphdr *ip = (struct iphdr *)(data + 14);
					uint16_t size = ntohs(ip->tot_len) + 14;
				
					pkthdr.caplen = size;
					pkthdr.len = size;
				
					out = fopen(PATH, "a+");
					fwrite(&pkthdr,sizeof(struct pcap_pkthdr_t),1,out);
					fwrite(data,size,1,out);
				//	char buf[] = "1234";
				//	fwrite(buf, 4, 1, out);
					fclose(out);
				}
				pthread_mutex_unlock(&write_lock);

				free(data);
			}
			else
			{
				iii++;
				printf("The reassemble process not complete!%d.\n",iii);
			}

			free(n->packet_content);
			free(n);
		}
	}
}

void ip_packet_callback(unsigned char *argument, \
		const struct pcap_pkthdr* pcap_header, \
		const unsigned char *packet_content)
{
	/*struct node *tmp_node = create(packet_content);*/
	struct iphdr *ip = (struct iphdr*)(packet_content + 14);

	int size = ntohs(ip->tot_len) + 14;
	//fprintf(stdout, "size = %d\n", size);

	unsigned char *content = (unsigned char *)malloc(size);
	memcpy(content,packet_content,size);
	struct node *tmp_node = create(content);

	pthread_mutex_lock(&que_mtx);
	push(que,tmp_node);
	pthread_mutex_unlock(&que_mtx);
	//printf("In ip_packet_callback!()\n");
	//print((uint8_t *)tmp_node->packet_content);
	/*printf("\nIn processing function!\n");
	  print((uint8_t *)packet_content);
	  struct ipacket *pdata;
	  struct iphdr *ip = (struct iphdr *)(packet_content + MAC_HDRLEN);
	  uint16_t len = ntohs(ip->tot_len) + MAC_HDRLEN;
	//printf("The packet's length is %d.\n",len);
	pdata = (struct ipacket *)malloc(sizeof(struct ipacket));
	memset(pdata,0,sizeof(struct ipacket));

	pdata->p_data = (uint8_t *)malloc(len);

	memcpy(pdata->p_data,packet_content,len);

	pdata->p_nh = (uint8_t *)malloc(sizeof(struct iphdr));

	memcpy(pdata->p_nh,ip,sizeof(struct iphdr));

	//struct iphdr *te = (struct iphdr *)pdata->p_nh;
	//printf("total len = %d\n",ntohs(te->tot_len));
	//	printf("pdata->p_nh->tot_len = %d\n",ntohs(pdata->p_nh->tot_len));
	uint8_t *data = ip_defrag(pdata);

	if(data)
	{
	//printf("------------------Packet after reassembled--------------------\n");
	struct ethhdr *ethptr;
	struct iphdr *ipptr;
	unsigned char *mac;
	ethptr=(struct ethhdr *)data;

	printf("\n----ethernet protocol(phydical layer)-----\n");
	printf("MAC source Address:\n");
	mac= (unsigned char *)ethptr->h_source;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*mac,*(mac+1),*(mac+2),*(mac+3),*(mac+4),*(mac+5));
	printf("MAC destination Address:\n");
	mac= (unsigned char *)ethptr->h_dest;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*mac,*(mac+1),*(mac+2),*(mac+3),*(mac+4),*(mac+5));
	printf("protocol:0x%04x\n",ntohs((uint16_t)ethptr->h_proto));
	printf("\n");
	print(data);
	}
	else
	{
	//printf("The reassemble process not complete!\n");
	}*/
}

void ethernet_packet_callback(unsigned char *argument, \
		const struct pcap_pkthdr* pcap_header, \
		const unsigned char *packet_content) 
{
	pcounter++;
	//printf("\nThis is the %uth packet we captures!",pcounter);

	//sleep(2);
	struct ethhdr *ethptr;
	ethptr=(struct ethhdr *)packet_content;
#if 0
	printf("\n----ethernet protocol(phydical layer)-----\n");
	printf("MAC source Address:\n");
	mac= (unsigned char *)ethptr->h_source;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*mac,*(mac+1),*(mac+2),*(mac+3),*(mac+4),*(mac+5));
	printf("MAC destination Address:\n");
	mac= (unsigned char *)ethptr->h_dest;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*mac,*(mac+1),*(mac+2),*(mac+3),*(mac+4),*(mac+5));
	printf("protocol:0x%04x\n",ntohs((uint16_t)ethptr->h_proto));
	printf("\n");
#endif
	switch(ntohs((uint16_t)ethptr->h_proto)) {
		case 0x0800:
//			printf("It is a IP protocol\n");
			ip_packet_callback(argument,pcap_header,packet_content);
			break;
		case 0x0806:
			printf("It is a ARP protocol\n");
			printf("\n");
			break;
		case 0x8035:
			printf("It is a RARP protocol\n");
			printf("\n");
			break;
		default:
			printf("Unkonwn protocol!\n");
			printf("\n");
			break;

	}
}

int main()
{
	ip_frag_init();

//	pthread_mutex_init(&write_lock,NULL);

	out = fopen(PATH, "w+");
	fwrite(pfh,sizeof(pfh),1,out);
	fclose(out);


	//pthread_mutex_init(&(que->pq_mtx),NULL);
	pthread_mutex_init(&que_mtx,NULL);

	que = (struct queue *)malloc(sizeof(struct queue));
	if (!que)
	{
		printf("Require memory failed!\n");
		exit(-1);
	}
	memset(que,0,sizeof(struct queue));

	pcap_t *pt;
	char errbuf[128];
	struct bpf_program fp;
	bpf_u_int32 netp = 0;
	const char *filter = "";

	/*if (pcap_findalldevs(&alldevs,errbuf)==-1) 
	  {
	  fprintf(stderr,"find interface failed!\n");
	  return;
	  }

	  for (d=alldevs;d;d=d->next)
	  {
	  printf("%d. %s\n",++i,d->name);
	  if (d->description)
	  printf("(%s)\n",d->description);
	  else
	  printf("(no description available)\n");
	  }

	  if (i==1)
	  dev=alldevs->name;
	  else 
	  {
	  printf("input a interface:(1-%d)",i);
	  scanf("%d",&inum);
	  if (inum<1||inum>i) 
	  {
	  printf("interface number out of range\n");
	  return;
	  }

	  for (d=alldevs,i=1;i<inum;d=d->next,i++);
	  dev=d->name;
	  }

	  printf("dev:%s\n",dev);

	  ret=pcap_lookupnet(dev,&netp,&maskp,errbuf);

	  if (ret==-1)
	  {
	  fprintf(stderr,"%s\n",errbuf);
	  return;
	  }

	  pt=pcap_open_live(dev,BUFSIZ,1,pcap_time_out,errbuf);*/

	pt = pcap_open_offline(SOURCE, errbuf);

	if (pt==NULL)
	{
		fprintf(stderr,"open error :%s\n",errbuf);
		return 0;
	}

	if (pcap_compile(pt,&fp,filter,0,netp)==-1) 
	{
		fprintf(stderr,"compile error\n");
		return 0;
	}

	if (pcap_setfilter(pt,&fp)==-1) 
	{
		fprintf(stderr,"setfilter error\n");
		return 0;
	}

	for (; threadNumber < THREAD_NUM; threadNumber++)
	{
		pthread_create(&thr[threadNumber],NULL,multi_func,(void *)&threadNumber);
		sleep(1);
	}

	pcap_loop(pt,0,ethernet_packet_callback,NULL);

	pcap_close(pt);

//	sleep(2);
//	exit(0);

	for (threadNumber = 0; threadNumber < THREAD_NUM; threadNumber++)
	{
		pthread_join(thr[threadNumber], NULL);
	}
	
	return 0;
}
