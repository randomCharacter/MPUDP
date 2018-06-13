#include "common.h"

pcap_if_t *select_device(pcap_if_t** devices) {
	int device_number;
	uint8_t i = 0;
	pcap_if_t *device;
	char error_buffer[PCAP_ERRBUF_SIZE];	// Error buffer

	if (pcap_findalldevs(devices, error_buffer) == -1) {
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return NULL;
	}

	for (device = *devices; device; device = device->next) {
		printf("%d. %s\n", ++i, device->name);
	}

	if (i == 0) {
		printf("\nNo interfaces found! Make sure libpcap/WinPcap is installed.\n");
		return NULL;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &device_number);

	if (device_number < 1 || device_number > i) {
		printf("\nInterface number out of range.\n");
		return NULL;
	}

	for (device = *devices, i = 0; i < device_number - 1; device = device->next, i++) {}

	return device;
}

int set_filter(pcap_if_t* device, pcap_t* device_handle, const char* filter) {
	unsigned int netmask;
	struct bpf_program fcode;

	if (!device->addresses->netmask) {
		netmask = 0;
	} else {
		netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.s_addr;
	}

	if (pcap_compile(device_handle, &fcode, filter, 1, netmask) < 0) {
		printf("\nInvalid filter!\n");
		return 1;
	}
	if (pcap_setfilter(device_handle, &fcode) < 0) {
		printf("\nUnable to set the filter!\n");
		return 1;
	}

	return 0;
}
