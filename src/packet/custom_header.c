#include "custom_header.h"

custom_header create_custom_header(uint16_t seq_no) {
	custom_header ch;
	ch.seq_no = ntohs(seq_no);
	return ch;
}
