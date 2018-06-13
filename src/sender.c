#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "debug.h"
#include "packet/packet.h"
#include "file_utils.h"

// Addresses
#define FILTER CONSTRUCT_FILTER(SENDER_PORT)

uint8_t src_eth_mac_address[6] = { 0x74, 0xe6, 0xe2, 0x1c, 0xdf, 0x7c };
uint8_t src_eth_ip_address[4] = { 192, 168, 0, 101 };
uint8_t src_wifi_mac_address[6] = { 0x4c, 0xbb, 0x58, 0x36, 0xd2, 0x22 };
uint8_t src_wifi_ip_address[4] = { 192, 168, 43, 90 };

uint8_t dst_eth_mac_address[6] = { 0xb8, 0x27, 0xeb, 0x10, 0x0f, 0x81 };
uint8_t dst_eth_ip_address[4] = { 192, 168, 0, 100 };
uint8_t dst_wifi_mac_address[6] = { 0x00, 0x0f, 0x60, 0x05, 0x32, 0xf1 };
uint8_t dst_wifi_ip_address[4] = { 192, 168, 43, 233 };

pcap_if_t *wifi_device;
pcap_if_t *eth_device;
pcap_t *eth_device_handle;
pcap_t *wifi_device_handle;

int eth_alive = 1;
int wifi_alive = 1;

unsigned char wifi_ack = 0;
unsigned char eth_ack = 0;

int eth_finished = 0, wifi_finished = 0;

unsigned char *memory;
unsigned char *received;
int bytes;
int next_packet = 0;
int packet_no;
int finished = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
char error_buffer[PCAP_ERRBUF_SIZE];

void loop_handler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data) {
	packet *p = (packet*) packet_data;
	int pack = *(int*) param;

	if (strcmp((char*) p->data, "ACK") == 0 && pack == ntohs(p->cus_h.seq_no)) {
		received[pack] = 1;
		debug("ACK for %u\n", ntohs(p->cus_h.seq_no));
	}
}

void *wake_up_function(void *param) {
	debug("Wake up thread created\n");
	while (1) {
		if (!eth_alive && !wifi_alive) {
			printf("FATAL ERROR: Both interfaces dead!\n");
			exit(-1);
		}
		eth_alive = 1;
		wifi_alive = 1;
		sleep(WAKE_UP_TIMEOUT);
	}
}

void *wifi_thread_function(void *param) {
	debug("Thread wifi created\n");

	while (next_packet < packet_no) {
		pthread_mutex_lock(&mutex);
		int pack = next_packet++;
		pthread_mutex_unlock(&mutex);
		debug("wifi: next_packet=%d, packet_no=%d\n", next_packet, packet_no);
		ethernet_header eh = create_eth_header(dst_wifi_mac_address, src_wifi_mac_address);
		ip_header ih = create_ip_header(MAX_DATA_SIZE, src_wifi_ip_address, dst_wifi_ip_address);
		udp_header uh = create_udp_header(SENDER_PORT, RECEIVER_PORT, MAX_DATA_SIZE);
		custom_header ch = create_custom_header(pack);
		size_t data_size = (pack != packet_no - 1) ? MAX_DATA_SIZE : bytes % MAX_DATA_SIZE;
		size_t packet_size = data_size + sizeof(headers);
		packet *p = create_packet(eh, ih, uh, ch, memory + MAX_DATA_SIZE * pack, data_size);
		int retries = 0;

		while (!received[pack]) {
			if (wifi_alive) {
				pcap_sendpacket(wifi_device_handle, (unsigned char*) p, packet_size);
				debug("Sent packet %d over wifi\n", pack);
				pcap_dispatch(wifi_device_handle, 1, loop_handler, (unsigned char *)&pack);

				retries++;
				if (received[pack]) {
					retries = 0;
				} else {
					usleep(SLEEP_TIMEOUT);
				}
				if (retries >= MAX_RETRIES) {
					debug("WIFI is dead\n");
					wifi_alive = 0;
				}
			} else if (wifi_finished) {
				pcap_sendpacket(eth_device_handle, (unsigned char*) p, packet_size);
				debug("Sent packet %d over eth (wifi dead)\n", pack);
				pcap_dispatch(eth_device_handle, 1, loop_handler, (unsigned char *)&pack);
				if (!received[pack]) {
					usleep(SLEEP_TIMEOUT);
				}
			}
		}
		free(p);
	}
	debug("Thread wifi finished\n");
	wifi_finished = 1;
	return NULL;
}

void *eth_thread_function(void *param) {
	debug("Thread eth created\n");

	while (next_packet < packet_no) {
		pthread_mutex_lock(&mutex);
		int pack = next_packet++;
		pthread_mutex_unlock(&mutex);
		debug("eth: next_packet=%d, packet_no=%d\n", next_packet, packet_no);
		ethernet_header eh = create_eth_header(dst_eth_mac_address, src_eth_mac_address);
		ip_header ih = create_ip_header(MAX_DATA_SIZE, src_eth_ip_address, dst_eth_ip_address);
		udp_header uh = create_udp_header(SENDER_PORT, RECEIVER_PORT, MAX_DATA_SIZE);
		custom_header ch = create_custom_header(pack);
		size_t data_size = (pack != packet_no - 1) ? MAX_DATA_SIZE : bytes % MAX_DATA_SIZE;
		size_t packet_size = data_size + sizeof(headers);
		packet *p = create_packet(eh, ih, uh, ch, memory + MAX_DATA_SIZE * pack, data_size);
		int retries = 0;

		while (!received[pack]) {
			if (eth_alive) {
				pcap_sendpacket(eth_device_handle, (unsigned char*)p, packet_size);
				debug("Sent packet %d over eth\n", pack);
				pcap_dispatch(eth_device_handle, 1, loop_handler, (unsigned char*) &pack);
				retries++;
				debug("loop ended\n");
				if (received[pack]) {
					retries = 0;
				} else {
					usleep(SLEEP_TIMEOUT);
				}
				if (retries >= MAX_RETRIES) {
					debug("ETH is dead\n");
					eth_alive = 0;
				}
			} else if (eth_finished) {
				pcap_sendpacket(wifi_device_handle, (unsigned char*) p, packet_size);
				debug("Sent packet %d over wifi (eth dead)\n", pack);
				pcap_dispatch(wifi_device_handle, 1, loop_handler, (unsigned char*) &pack);
				if (!received[pack]) {
					usleep(SLEEP_TIMEOUT);
				}
			}
		}
		free(p);
	}
	eth_finished = 1;
	debug("Thread eth finished\n");
	return NULL;
}

void wifi_send_file_size(pcap_t *device_handle) {
	ethernet_header eh = create_eth_header(dst_wifi_mac_address, src_wifi_mac_address);
	ip_header ih = create_ip_header(sizeof(int), src_wifi_ip_address, dst_wifi_ip_address);
	udp_header uh = create_udp_header(SENDER_PORT, RECEIVER_PORT, sizeof(int));
	custom_header ch = create_custom_header(-1);
	packet *p = create_packet(eh, ih, uh, ch, (unsigned char*) &bytes, sizeof(int));
	size_t packet_size = sizeof(headers) + sizeof(int);
	pcap_sendpacket(device_handle, (unsigned char*) p, packet_size);
	free(p);
}

void eth_send_file_size(pcap_t *device_handle) {
	ethernet_header eh = create_eth_header(dst_eth_mac_address, src_eth_mac_address);
	ip_header ih = create_ip_header(sizeof(int), src_eth_ip_address, dst_eth_ip_address);
	udp_header uh = create_udp_header(SENDER_PORT, RECEIVER_PORT, sizeof(int));
	custom_header ch = create_custom_header(-1);
	packet *p = create_packet(eh, ih, uh, ch, (unsigned char *)&bytes, sizeof(int));
	size_t packet_size = sizeof(headers) + sizeof(int);
	pcap_sendpacket(device_handle, (unsigned char*) p, packet_size);
	free(p);
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
											)) == NULL)	{
		printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", eth_device->name);
		pcap_freealldevs(devices);
		return -1;
	}

	// Check the link layer. We support only Ethernet for simplicity.
	if (pcap_datalink(eth_device_handle) != DLT_EN10MB) {
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}

	if (set_filter(eth_device, eth_device_handle, FILTER)) {
		return -1;
	}

	if (pcap_setnonblock(eth_device_handle, 1, error_buffer) == -1) {
		return -1;
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

	if (set_filter(wifi_device, wifi_device_handle, FILTER)) {
		return -1;
	}

	if (pcap_setnonblock(wifi_device_handle, 1, error_buffer) == -1) {
		return -1;
	}

	// Read data from file
	FILE *f = fopen(argv[1], "rb");
	bytes = load_file_to_memory(f, &memory);
	packet_no = bytes / MAX_DATA_SIZE + 1;
	received = (unsigned char*) malloc(packet_no);
	memset(received, 0, packet_no);
	debug("bytes: %d\n", bytes);

	printf("Sending file %s\n", argv[1]);
	printf("Number of packets: %d\n", packet_no);

	// Get start time
	clock_t start = clock();

	debug("sending file size\n");
	eth_send_file_size(eth_device_handle);
	wifi_send_file_size(wifi_device_handle);

	pthread_t *wifi_thread, *eth_thread;
	wifi_thread = (pthread_t*) malloc(sizeof(pthread_t));
	eth_thread = (pthread_t*) malloc(sizeof(pthread_t));

	pthread_create(eth_thread, NULL, &wifi_thread_function, NULL);
	pthread_create(wifi_thread, NULL, &eth_thread_function, NULL);

	pthread_t *wake_up_thread;
	wake_up_thread = (pthread_t*) malloc(sizeof(pthread_t));
	pthread_create(wake_up_thread, NULL, &wake_up_function, NULL);

	pthread_detach(*wake_up_thread);

	pthread_join(*wifi_thread, NULL);
	pthread_join(*eth_thread, NULL);

	debug("threads joined\n");

	clock_t end = clock();
	float time = ((float) end - start) / CLOCKS_PER_SEC;
	float speed = bytes / time;

	printf("Time %.2f s\n", time);
	printf("Speed %.2f kbps\n", speed / 1024);

	// Free all resources
	free(memory);
	free(received);
	free(wifi_thread);
	free(eth_thread);
	free(wake_up_thread);
	pcap_freealldevs(devices);

	return 0;
}
