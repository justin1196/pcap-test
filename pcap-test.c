#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "pcap-test.h"
#include <netinet/in.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

bool check_tcp(uint8_t protocol){
	if(protocol==6)
		return false;
	else
		return true;	
}
bool check_data(uint16_t length,uint8_t protocol){
	int x=0;
	x=(protocol*4)-20;
	if(length==((40+x)*256)){
		printf("NO DATA\n\n");
		return true;
	}
	else 
		return false;

}

void capture_mac(uint8_t* src, uint8_t* dst){
	printf("[SRC MAC]  ");
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n",src[0],src[1],src[2],src[3],src[4],src[5]);
	printf("[DST MAC]  ");
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n\n",dst[0],dst[1],dst[2],dst[3],dst[4],dst[5]);
}
void capture_ip(uint8_t* src, uint8_t* dst){
	printf("[SRC IP]  ");
    printf("%u.%u.%u.%u\n",src[0],src[1],src[2],src[3]);
	printf("[DST IP]  ");
	printf("%u.%u.%u.%u\n\n",dst[0],dst[1],dst[2],dst[3]);
}
void capture_port(uint16_t src, uint16_t dst){
	printf("[SRC PORT]  ");
	printf("%u\n", src);
	printf("[DST PORT]  ");
	printf("%u\n\n", dst);
}
void capture_data(uint8_t protocol,uint8_t* data){
	int x=0;
	x=(protocol*4)-20;
	printf("[DATA]  ");
	printf("%X|%X|%X|%X|%X|%X|%X|%X\n\n", data[x+0],data[x+1],data[x+2],data[x+3],data[x+4],data[x+5],data[x+6],data[x+7]);
}


int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		my_packet* real_packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		real_packet = (my_packet*)packet;
		printf("%u bytes captured\n", header->caplen);
		if(check_tcp(real_packet->ip_p)) continue;
		capture_mac(real_packet->ether_dhost,real_packet->ether_shost);
		capture_ip(real_packet->ip_src,real_packet->ip_drc);
		capture_port(ntohs(real_packet->th_sport),ntohs(real_packet->th_dport));
		if(check_data(real_packet->ip_len,real_packet->th_off)) continue;
		capture_data(real_packet->th_off,real_packet->data);
	
		
	}

	pcap_close(pcap);
}