#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"


/* Packet building functions */
uint8_t* build_eth_frame(sr_ethernet_hdr_t *eth_hdr, uint8_t *data, int datalen) {
	uint8_t* buf;
	int packet_length;
	uint16_t checksum;
	
	packet_length = sizeof(sr_ethernet_hdr_t) + (sizeof(uint8_t) * datalen) + 2;
	/* Packet */
	buf = (uint8_t*) malloc (packet_length);
	memcpy (buf, eth_hdr, sizeof(sr_ethernet_hdr_t));
	memcpy (buf + sizeof(sr_ethernet_hdr_t), data, datalen);
	/* Checksum */
	checksum = cksum (buf, packet_length - 2);
	memcpy (buf + packet_length - 2, &checksum, 2);
	
	return buf;
}

uint8_t* build_ip_packet(sr_ip_hdr_t *ip_hdr, uint8_t *data, int datalen) {
	uint8_t* buf;
	int packet_length;
	
	packet_length = sizeof(sr_ip_hdr_t) + (sizeof(uint8_t) * datalen);
	buf = (uint8_t*) malloc (packet_length);
	memcpy (buf, ip_hdr, sizeof(sr_ip_hdr_t));
	memcpy (buf + sizeof(sr_ip_hdr_t), data, datalen);
	
	return buf;
}

uint8_t* build_icmp_packet(sr_icmp_hdr_t *icmp_hdr) {
	uint8_t* buf;
	buf = (uint8_t*) malloc (sizeof(sr_icmp_hdr_t));
	memcpy (buf, icmp_hdr, sizeof(sr_icmp_hdr_t));
	return buf;
}

uint8_t* build_icmp_t3_packet(sr_icmp_t3_hdr_t *icmp_t3_hdr) {
	uint8_t* buf;
	buf = (uint8_t*) malloc (sizeof(sr_icmp_t3_hdr_t));
	memcpy (buf, icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
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