#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_router.h"


/* Packet building functions */
uint8_t* build_eth_frame(uint8_t ether_dhost[], uint8_t ether_shost[], uint16_t ether_type, uint8_t *data, int datalen) {
	uint8_t* buf;
	int packet_length;
	uint16_t checksum;
	struct sr_ethernet_hdr hdr;
	memcpy(hdr.ether_dhost,ether_dhost,ETHER_ADDR_LEN); /* destination ethernet address */
	memcpy(hdr.ether_shost,ether_shost,ETHER_ADDR_LEN); /* source ethernet address */
    hdr.ether_type = ether_type;                     /* packet type ID */
	
	packet_length = sizeof(sr_ethernet_hdr_t) + (sizeof(uint8_t) * datalen) + 2;
	/* Packet */
	buf = (uint8_t*) malloc (packet_length);
	memcpy (buf, &hdr, sizeof(sr_ethernet_hdr_t));
	memcpy (buf + sizeof(sr_ethernet_hdr_t), data, datalen);
	/* Checksum */
	checksum = cksum (buf, packet_length - 2);
	memcpy (buf + packet_length - 2, &checksum, 2);
	
	return buf;
}

uint8_t* build_ip_packet(uint16_t ip_id, uint16_t ip_off, uint8_t ip_p, uint32_t ip_src, uint32_t ip_dst, 
							uint8_t *data, int datalen) {
	uint8_t* buf;
	int packet_length;
	struct sr_ip_hdr hdr;
    hdr.ip_hl = 5;		/* header length */
    hdr.ip_v = 4;		/* version */
    hdr.ip_tos = 0;			/* type of service */
   
    hdr.ip_id = ip_id;			/* identification */
    hdr.ip_off = ip_off;			/* fragment offset field */
    hdr.ip_ttl = 64;			/* time to live */
    hdr.ip_p = ip_p;			/* protocol */
    hdr.ip_sum = 0;			/* checksum */
    hdr.ip_src = ip_src;
	hdr.ip_dst = ip_dst;	/* source and dest address */
	hdr.ip_sum = cksum((void*)(&hdr), sizeof(struct sr_ip_hdr));	
	
	packet_length = sizeof(sr_ip_hdr_t) + (sizeof(uint8_t) * datalen);
	hdr.ip_len = packet_length;			/* total length */
	buf = (uint8_t*) malloc (packet_length);
	memcpy (buf, &hdr, sizeof(sr_ip_hdr_t));
	memcpy (buf + sizeof(sr_ip_hdr_t), data, datalen);
	
	return buf;
}


uint8_t* build_icmp_packet(uint8_t icmp_type, uint8_t icmp_code) {
	uint8_t* buf;
	
	struct sr_icmp_hdr hdr;
	hdr.icmp_type = icmp_type;
	hdr.icmp_code = icmp_code;
	hdr.icmp_sum = 0;
	hdr.icmp_sum = cksum((void*)(&hdr), sizeof(struct sr_icmp_hdr));
	
	buf = (uint8_t*) malloc (sizeof(sr_icmp_hdr_t));
	memcpy (buf, &hdr, sizeof(sr_icmp_hdr_t));
	return buf;
}

uint8_t* build_icmp_t3_packet(uint8_t icmp_type, uint8_t icmp_code, uint8_t* failed_ip_packet) {
	uint8_t* buf;
	struct sr_icmp_t3_hdr hdr;
	
	hdr.icmp_type = icmp_type;
	hdr.icmp_code = icmp_code;
	hdr.icmp_sum = 0;
	hdr.unused = 0;
	hdr.next_mtu = 0; /*only used for code 4, which is out of scope of this assignment. */
	if(sizeof(struct sr_ip_hdr)+8 != ICMP_DATA_SIZE){
		Debug("init_sr_icmp_t3_hdr: sizeof(struct sr_ip_hdr)+8 != ICMP_DATA_SIZE");
	}
	
	memcpy(&hdr.data,failed_ip_packet,sizeof(struct sr_ip_hdr));/*Data has IP header + 1st 8 bytes of payload */
	memcpy((&hdr.data)+sizeof(struct sr_ip_hdr),failed_ip_packet,8);
	hdr.icmp_sum = cksum((void*)(&hdr), sizeof(struct sr_icmp_t3_hdr));
	
	buf = (uint8_t*) malloc (sizeof(sr_icmp_t3_hdr_t));
	memcpy (buf, &hdr, sizeof(sr_icmp_t3_hdr_t));
	return buf;
}

uint8_t* build_arp_packet(sr_arp_hdr_t *arp_hdr) {
	uint8_t* buf;
	buf = (uint8_t*) malloc (sizeof(sr_arp_hdr_t));
	memcpy (buf, arp_hdr, sizeof(sr_arp_hdr_t));
	return buf;
}


/* Packet parsing functions */
sr_ethernet_hdr_t* parse_eth_frame(uint8_t *buf, uint8_t *payload) {
	payload = buf + sizeof(sr_ethernet_hdr_t);
	
	return (sr_ethernet_hdr_t*)buf;
}

sr_ip_hdr_t* parse_ip_packet(uint8_t *buf, uint8_t *payload) {
	payload = buf + sizeof(sr_ip_hdr_t);
	
	return (sr_ip_hdr_t*)buf;
}

sr_icmp_hdr_t* parse_icmp_packet(uint8_t *buf) {
	return (sr_icmp_hdr_t*)buf;
}
sr_icmp_t3_hdr_t* parse_icmp_t3_packet(uint8_t *buf) {
	return (sr_icmp_t3_hdr_t*)buf;
}
sr_arp_hdr_t* parse_arp_packet(uint8_t *buf) {
	return (sr_arp_hdr_t*)buf;
}