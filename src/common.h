#pragma once

#include <pcap.h>
#include <arpa/inet.h>
#include <stdint.h>

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define CONSTRUCT_FILTER(PORT) "udp and dst port " STR(PORT)

pcap_if_t *select_device(pcap_if_t** devices);

int set_filter(pcap_if_t *device, pcap_t *device_handle, const char *filter);
