#pragma once

#include <stdlib.h>

#include "../config.h"
#include "../global.h"
#include "custom_header.h"
#include "eth_header.h"
#include "ip_header.h"
#include "udp_header.h"

typedef PACKED_STRUCT() {
	ethernet_header eth_h;
	ip_header ip_h;
	udp_header udp_h;
	custom_header cus_h;
	unsigned char data[MAX_DATA_SIZE];
} packet;

typedef PACKED_STRUCT() {
	ethernet_header eth_h;
	ip_header ip_h;
	udp_header udp_h;
	custom_header cus_h;
} headers;

packet *create_packet(ethernet_header eh, ip_header ih, udp_header uh, custom_header ch, unsigned char *data, size_t len);

u_int16_t calculate_udp_checksum(unsigned char *p, size_t size);
