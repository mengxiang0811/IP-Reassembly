#include "checksum.h"

uint16_t cksum(struct iphdr *ip,uint16_t len)
{
	uint32_t sum = 0;

	while (len > 1)
	{
		sum += (*((uint16_t *) ip))++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if (len)
		sum += (uint16_t)*(unsigned char *)ip;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}

uint16_t checksum_t(uint16_t *buf,int nword)
{
        uint32_t sum;
        
        for(sum=0;nword>0;nword--)
            sum += *buf++;
        sum = (sum>>16) + (sum&0xffff);
        sum += (sum>>16);
        
        return ~sum;
}
