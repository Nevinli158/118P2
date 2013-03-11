#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_router.h"
#include "sr_headers.h"


/* Packet building functions */
uint8_t* build_eth_frame(uint8_t *ether_dhost, uint8_t *ether_shost, uint16_t ether_type, uint8_t *data, int datalen) {
	uint8_t* buf;
	int packet_length;
	uint32_t checksum;
	struct sr_ethernet_hdr hdr;
	memcpy(hdr.ether_dhost,ether_dhost,ETHER_ADDR_LEN); /* destination ethernet address */
	memcpy(hdr.ether_shost,ether_shost,ETHER_ADDR_LEN); /* source ethernet address */
    hdr.ether_type = htons(ether_type);                     /* packet type ID */
	
	packet_length = sizeof(sr_ethernet_hdr_t) + (sizeof(uint8_t) * datalen) + FCS_SIZE;
	/* Packet */
	buf = (uint8_t*) malloc (packet_length);
	memcpy (buf, &hdr, sizeof(sr_ethernet_hdr_t));
	memcpy (buf + sizeof(sr_ethernet_hdr_t), data, datalen);
	/* Checksum */
	checksum = cksum(buf, packet_length - FCS_SIZE);
	checksum = htonl(checksum);
	memcpy (buf + packet_length - FCS_SIZE, &checksum, FCS_SIZE);
	
	return buf;
}

uint8_t* build_ip_packet(uint16_t ip_id, uint16_t ip_off, uint8_t ip_p, uint32_t ip_src, uint32_t ip_dst, 
							uint8_t *data, int datalen) {
	uint8_t* buf;
	uint16_t packet_length;
	uint16_t checksum;
	
	struct sr_ip_hdr hdr;
	#if __BYTE_ORDER == __LITTLE_ENDIAN
		hdr.ip_hl = 4;		/* actually the version */
		hdr.ip_v = 5;		/* actually the header length */
	#else
		hdr.ip_hl = 5;		/* header length */
		hdr.ip_v = 4;		/* version */
	#endif 
	
    hdr.ip_tos = 0;			/* type of service */
    hdr.ip_id = htons(ip_id);			/* identification */
    hdr.ip_off = htons(ip_off);			/* fragment offset field */
    hdr.ip_ttl = 64;			/* time to live */
    hdr.ip_p = ip_p;			/* protocol */
    hdr.ip_sum = 0;			/* checksum is zeroed out for checksum computation */
    hdr.ip_src = htonl(ip_src);
	hdr.ip_dst = htonl(ip_dst);	/* source and dest address */
	checksum = cksum((void*)(&hdr), sizeof(struct sr_ip_hdr));
	hdr.ip_sum = htons(checksum);
	packet_length = sizeof(sr_ip_hdr_t) + (sizeof(uint8_t) * datalen);
	hdr.ip_len = htons(packet_length);			/* total length */
	
	buf = (uint8_t*) malloc (packet_length);
	memcpy (buf, &hdr, sizeof(sr_ip_hdr_t));
	memcpy (buf + sizeof(sr_ip_hdr_t), data, datalen);
	
	return buf;
}


uint8_t* build_icmp_packet(uint8_t icmp_type, uint8_t icmp_code) {
	uint8_t* buf;
	uint16_t checksum;
	
	struct sr_icmp_hdr hdr;
	hdr.icmp_type = icmp_type;
	hdr.icmp_code = icmp_code;
	hdr.icmp_sum = 0;	/* checksum is zeroed out for checksum computation */
	checksum = cksum((void*)(&hdr), sizeof(struct sr_icmp_hdr));
	hdr.icmp_sum = htons(checksum);
	
	buf = (uint8_t*) malloc (sizeof(sr_icmp_hdr_t));
	memcpy (buf, &hdr, sizeof(sr_icmp_hdr_t));
	return buf;
}

uint8_t* build_icmp_t3_packet(uint8_t icmp_type, uint8_t icmp_code, uint8_t* failed_ip_packet) {
	uint8_t* buf;
	uint16_t checksum;
	struct sr_icmp_t3_hdr hdr;
	
	hdr.icmp_type = icmp_type;
	hdr.icmp_code = icmp_code;
	hdr.icmp_sum = 0;	/* checksum is zeroed out for checksum computation */
	hdr.unused = 0;
	hdr.next_mtu = 0; /*only used for code 4, which is out of scope of this assignment. */
	if(sizeof(struct sr_ip_hdr)+8 != ICMP_DATA_SIZE){
		Debug("init_sr_icmp_t3_hdr: sizeof(struct sr_ip_hdr)+8 != ICMP_DATA_SIZE");
	}
	memcpy(&hdr.data,failed_ip_packet,sizeof(struct sr_ip_hdr));/*Data has IP header + 1st 8 bytes of payload */
	memcpy((&hdr.data)+sizeof(struct sr_ip_hdr),failed_ip_packet,8);
	
	checksum = cksum((void*)(&hdr), sizeof(struct sr_icmp_t3_hdr));
	hdr.icmp_sum = htons(checksum);
	
	buf = (uint8_t*) malloc (sizeof(sr_icmp_t3_hdr_t));
	memcpy (buf, &hdr, sizeof(sr_icmp_t3_hdr_t));
	return buf;
}

uint8_t* build_arp_packet(unsigned short ar_op, unsigned char ar_sha[], uint32_t ar_sip, unsigned char ar_tha[],
							uint32_t ar_tip) {
	uint8_t* buf;
	struct sr_arp_hdr hdr;
    hdr.ar_hrd = htons(arp_hrd_ethernet);             /* format of hardware address   */
    hdr.ar_pro = htons(ethertype_ip);             /* format of protocol address   */
    hdr.ar_hln = ETHER_ADDR_LEN;             /* length of hardware address   */
    hdr.ar_pln = 4;             /* length of protocol address   */
    hdr.ar_op = htons(ar_op);              /* ARP opcode (command)         */
	memcpy(hdr.ar_sha,ar_sha,ETHER_ADDR_LEN); /* sender hardware address      */
    hdr.ar_sip = htonl(ar_sip);             /* sender IP address            */
	memcpy(hdr.ar_tha,ar_tha,ETHER_ADDR_LEN); /* target hardware address      */
    hdr.ar_tip = htonl(ar_tip);             /* target IP address            */
	
	buf = (uint8_t*) malloc (sizeof(sr_arp_hdr_t));
	memcpy (buf, &hdr, sizeof(sr_arp_hdr_t));
	return buf;
}


/* Packet parsing functions */
sr_ethernet_hdr_t* parse_eth_frame(uint8_t *buf, uint8_t **payload) {
	*payload = buf + sizeof(sr_ethernet_hdr_t);
	
	return (sr_ethernet_hdr_t*)buf;
}

sr_ip_hdr_t* parse_ip_packet(uint8_t *buf, uint8_t **payload) {
	*payload = buf + sizeof(sr_ip_hdr_t);
	
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