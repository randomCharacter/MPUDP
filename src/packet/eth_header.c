#include "eth_header.h"

ethernet_header create_eth_header(const uint8_t dst_address[6], const uint8_t src_address[6]) {
	ethernet_header eh;
	memcpy(eh.dst_address, dst_address, 6);
	memcpy(eh.src_address, src_address, 6);
	eh.type = htons(NEXT_TYPE);

	return eh;
}

void set_eth_dst_address(ethernet_header *eh, const uint8_t dst_address[6]) {
	memcpy(eh->dst_address, dst_address, 6);
}

void set_eth_src_address(ethernet_header *eh, const uint8_t src_address[6]) {
	memcpy(eh->src_address, src_address, 6);
}

void set_eth_next_layer(ethernet_header *eh, uint16_t type) {
	eh->type = type;
}

