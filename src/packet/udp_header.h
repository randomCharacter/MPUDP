#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "custom_header.h"

typedef struct udp_header {
	uint16_t src_port;			// Source port
	uint16_t dest_port;			// Destination port
	uint16_t datagram_length;	// Length of datagram including UDP header and data
	uint16_t checksum;			// Header checksum
} udp_header;

udp_header create_udp_header(uint16_t src_port, uint16_t dest_port, uint16_t data_size);

uint16_t get_udp_src_port(udp_header *uh);

uint16_t get_udp_dst_port(udp_header *uh);

uint16_t get_udp_checksum(udp_header *uh);

void set_udp_checksum(udp_header *uh, uint16_t checksum);
