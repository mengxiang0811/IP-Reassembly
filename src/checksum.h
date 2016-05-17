#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <netinet/ip.h>
#include <stdint.h>

uint16_t cksum(struct iphdr *ip,uint16_t len);
uint16_t checksum_t(uint16_t *buf,int nword);

#endif
