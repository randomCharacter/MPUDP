#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "debug.h"
#include "file_utils.h"
#include "packet/packet.h"

#define FILTER "udp and dst port 50055"

pcap_if_t *wifi_device;
pcap_if_t *eth_device;
pcap_t *eth_device_handle;
pcap_t *wifi_device_handle;

size_t file_size = 0;
unsigned char *memory = NULL;
unsigned char *received = NULL;
int packet_no = 0;
int finished = 0;

pthread_t *wifi_thread;
pthread_t *eth_thread;

void loop_handler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data) {
	packet *p = (packet*) packet_data;
	pcap_t *device_handle = (pcap_t*) param;
	int pack = ntohs(p->cus_h.seq_no);
	uint16_t checksum = ntohs(p->udp_h.checksum);

	debug("Packet received %u\n", pack);
	size_t data_size = htons(p->udp_h.datagram_length) - sizeof(udp_header) - sizeof(custom_header);
	if (checksum == calculate_udp_checksum((unsigned char*) &(p->cus_h), data_size + sizeof(custom_header))) {
		received[pack] = 1;
		// Write to memory
		memcpy(memory + MAX_DATA_SIZE * pack, p->data, data_size);
		// Send ACK
		ethernet_header eh = create_eth_header(p->eth_h.src_address, p->eth_h.dst_address);
		ip_header ih = create_ip_header(4, p->ip_h.dst_addr, p->ip_h.src_addr);
		udp_header uh = create_udp_header(RECEIVER_PORT, SENDER_PORT, 4);
		custom_header ch = create_custom_header(pack);
		packet *response = create_packet(eh, ih, uh, ch, (unsigned char*)"ACK", 4);
		pcap_sendpacket(device_handle, (void*)response, sizeof(headers) + 4);
		free(response);
		debug("Sent ACK for %d\n", pack);
	} else {
		debug("Checksum error for packet %d\n got %u, expected %u\n", pack, checksum, calculate_udp_checksum((unsigned char *)&(p->cus_h), data_size + sizeof(custom_header)));
	}
}

char all_packets_received() {
	char all_received = 1;
	for (int i = 0; i < packet_no; i++) {
		all_received = all_received && received[i];
		if (!all_received) {
			break;
		}
	}
	finished = all_received;
	return all_received;
}

void *wifi_thread_function(void *param) {
	debug("thread wifi created\n");

	while (!all_packets_received()) {
		pcap_loop(wifi_device_handle, 1, loop_handler, (unsigned char*)wifi_device_handle);
	}

	debug("thread wifi finished\n");
	pthread_cancel(*eth_thread);
	pcap_breakloop(eth_device_handle);
	return NULL;
}

void *eth_thread_function(void *param) {
	debug("thread eth created\n");

	while (!all_packets_received()) {
		pcap_loop(eth_device_handle, 1, loop_handler, (unsigned char*)eth_device_handle);
	}

	debug("thread eth finished\n");
	pthread_cancel(*wifi_thread);
	pcap_breakloop(wifi_device_handle);
	return NULL;
}

void get_size(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data) {
	packet *p = (packet*) packet_data;
	int s = *(int*)(p->data);
	debug("received size %d\n", s);
	if (file_size == 0) {
		file_size = s;
	} else if (file_size != s) {
		printf("FATAL ERROR: Wrong file size\n");
		exit(-1);
	}
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("Invalid arguments\n%s path/to/file\n", argv[0]);
		exit(-1);
	}

	if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
		printf("%s path/to/file\n", argv[0]);
		exit(-1);
	}

	pcap_if_t *devices;
	char error_buffer[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs(&devices, error_buffer) == -1) {
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}

	// ETHERNET DEVICE
	printf("Choose ethernet interface:\n");
	eth_device = select_device(&devices);

	// Check if device is valid
	if (eth_device == NULL) {
		pcap_freealldevs(devices);
		return -1;
	}

	// Open the capture device
	if ((eth_device_handle = pcap_open_live(eth_device->name, // name of the device
											65536,			  // portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
											1,				  // promiscuous mode
											TIMEOUT,		  // read timeout
											error_buffer	  // buffer where error message is stored
											)) == NULL) {
		printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", eth_device->name);
		pcap_freealldevs(devices);
		return -1;
	}

	// Check the link layer. We support only Ethernet for simplicity.
	if (pcap_datalink(eth_device_handle) != DLT_EN10MB) {
		printf("\nThis program works only on Ethernet networks.\n");
		return 1;
	}

	// Set filter
	if (set_filter(eth_device, eth_device_handle, FILTER)) {
		return 1;
	}

	// WI-FI DEVICE
	printf("Choose wi-fi interface:\n");
	wifi_device = select_device(&devices);

	// Check if device is valid
	if (wifi_device == NULL) {
		pcap_freealldevs(devices);
		return -1;
	}

	// Open the capture device
	if ((wifi_device_handle = pcap_open_live(wifi_device->name, // name of the device
											 65536,				// portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
											 1,					// promiscuous mode
											 TIMEOUT,			// read timeout
											 error_buffer		// buffer where error message is stored
											 )) == NULL) {
		printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", wifi_device->name);
		pcap_freealldevs(devices);
		return -1;
	}

	// Check the link layer. We support only Ethernet for simplicity.
	if (pcap_datalink(wifi_device_handle) != DLT_EN10MB) {
		printf("\nThis program works only on ethernet networks.\n");
		return -1;
	}

	// Set filter
	if (set_filter(wifi_device, wifi_device_handle, FILTER)) {
		return 1;
	}

	// Send size on both interfaces
	pcap_loop(eth_device_handle, 1, get_size, NULL);
	pcap_loop(wifi_device_handle, 1, get_size, NULL);

	// Get start time
	clock_t start = clock();

	packet_no = file_size / MAX_DATA_SIZE + 1;
	debug("packet_no=%d\n", packet_no);
	received = (unsigned char*) malloc(packet_no);
	memset(received, 0, packet_no);
	debug("allocated %d bytes of memory for received array\n", packet_no);
	size_t total_size = packet_no * MAX_DATA_SIZE;
	memory = (unsigned char*) malloc(total_size);
	debug("allocated %ld bytes of memory for memory array\n", sizeof(memory));

	eth_thread = (pthread_t*) malloc(sizeof(pthread_t));
	wifi_thread = (pthread_t*) malloc(sizeof(pthread_t));

	pthread_create(eth_thread, NULL, &wifi_thread_function, NULL);
	pthread_create(wifi_thread, NULL, &eth_thread_function, NULL);

	pthread_join(*wifi_thread, NULL);
	pthread_join(*eth_thread, NULL);


	debug("threads joined\n");

	debug("writing file to disk\n");

	FILE *f = fopen(argv[1], "wb");

	load_memory_to_file(f, memory, file_size);

	printf("File written to disk\n");

	clock_t end = clock();
	float time = ((float) end - start) / CLOCKS_PER_SEC;
	float speed = file_size / time;

	printf("Time %.2f s\n", time);
	printf("Speed %.2f kbps\n", speed / 1024);

	// Free all resources
	fclose(f);
	free(memory);
	free(received);
	free(wifi_thread);
	free(eth_thread);
	pcap_freealldevs(devices);

	return 0;
}
