#pragma once

#include <pcap.h>
#include <arpa/inet.h>
#include <stdint.h>

pcap_if_t *select_device(pcap_if_t** devices);

int set_filter(pcap_if_t *device, pcap_t *device_handle, const char *filter);
