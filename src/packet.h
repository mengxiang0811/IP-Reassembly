#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

struct ipacket
{
	uint8_t *p_data;
	uint8_t *p_nh;
};

#endif
