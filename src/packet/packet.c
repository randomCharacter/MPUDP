#include "packet.h"

packet* create_packet(ethernet_header eh, ip_header ih, udp_header uh, custom_header ch, unsigned char* data, size_t size) {
	packet *dp = (packet*) malloc(sizeof(packet));

	dp->eth_h = eh;
	dp->ip_h = ih;
	dp->udp_h = uh;
	dp->cus_h = ch;

	memcpy(dp->data, data, size);

	uint16_t checksum = calculate_udp_checksum((unsigned char*) &(dp->cus_h), size + sizeof(custom_header));
	set_udp_checksum(&(dp->udp_h), checksum);

	return dp;
}

u_int16_t calculate_udp_checksum(unsigned char *p, size_t size) {
	uint16_t checksum = 0;
	for (int i = 0; i < size; i++) {
		checksum += p[i];
	}

	return 0;//checksum;
}
