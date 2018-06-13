#pragma once

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define NEXT_TYPE 0x0800

typedef struct ethernet_header {
	uint8_t dst_address[6];	// destination address
	uint8_t src_address[6];	// Source address
	uint16_t type;			// Type of the next layer
} ethernet_header;

ethernet_header create_eth_header(const uint8_t dst_address[6], const uint8_t src_address[6]);

void set_eth_dst_address(ethernet_header *eh, const uint8_t dst_address[6]);

void set_eth_src_address(ethernet_header *eh, const uint8_t src_address[6]);

void set_eth_next_layer(ethernet_header *eh, uint16_t type);

