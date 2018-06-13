#include "udp_header.h"

udp_header create_udp_header(uint16_t src_port, uint16_t dest_port, uint16_t data_size) {
	udp_header uh;
	uh.src_port = ntohs(src_port);
	uh.dest_port = ntohs(dest_port);
	uh.datagram_length = htons(sizeof(udp_header) + sizeof(custom_header) + data_size);

	return uh;
}

uint16_t get_udp_src_port(udp_header *uh) {
	return htons(uh->src_port);
}

uint16_t get_udp_dst_port(udp_header *uh) {
	return htons(uh->dest_port);
}

uint16_t get_udp_length(udp_header *uh) {
	return htons(uh->datagram_length);
}

uint16_t get_udp_checksum(udp_header *uh) {
	return htons(uh->checksum);
}

void set_udp_checksum(udp_header *uh, uint16_t checksum) {
	uh->checksum = htons(checksum);
}
