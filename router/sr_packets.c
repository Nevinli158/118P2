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
	struct sr_ethernet_hdr hdr;
	memcpy(hdr.ether_dhost,ether_dhost,ETHER_ADDR_LEN); /* destination ethernet address */
	memcpy(hdr.ether_shost,ether_shost,ETHER_ADDR_LEN); /* source ethernet address */
    hdr.ether_type = ether_type;                     /* packet type ID */
	
	packet_length = sizeof(sr_ethernet_hdr_t) + (sizeof(uint8_t) * datalen);
	/* Packet */
	buf = (uint8_t*) malloc (packet_length);
	memcpy (buf, &hdr, sizeof(sr_ethernet_hdr_t));
	memcpy (buf + sizeof(sr_ethernet_hdr_t), data, datalen);
	
	return buf;
}

uint8_t* build_ip_packet(uint16_t ip_id, uint16_t ip_off, uint8_t ip_p, uint32_t ip_src, uint32_t ip_dst, 
							uint8_t *data, int datalen) {
	uint8_t* buf;
	uint16_t packet_length;
	uint16_t checksum;
	
	struct sr_ip_hdr hdr;

	hdr.ip_hl = 5;		/* header length */
	hdr.ip_v = 4;		/* version */
    hdr.ip_tos = 0;			/* type of service */
    hdr.ip_id = ip_id;			/* identification */
    hdr.ip_off = ip_off;			/* fragment offset field */
    hdr.ip_ttl = 64;			/* time to live */
    hdr.ip_p = ip_p;			/* protocol */
    hdr.ip_sum = 0;			/* checksum is zeroed out for checksum computation */
    hdr.ip_src = ntohl(ip_src);	/* source and dest address */
	hdr.ip_dst = ntohl(ip_dst);	/* need to convert to host order for checksum calculation */
	checksum = cksum((void*)(&hdr), sizeof(struct sr_ip_hdr));
	hdr.ip_src = htonl(ip_src);
	hdr.ip_dst = htonl(ip_dst);
	hdr.ip_sum = checksum;
	packet_length = sizeof(sr_ip_hdr_t) + (sizeof(uint8_t) * datalen);
	hdr.ip_len = packet_length;			/* total length */
	
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
	hdr.icmp_sum = checksum;
	
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
	hdr.icmp_sum = checksum;
	
	buf = (uint8_t*) malloc (sizeof(sr_icmp_t3_hdr_t));
	memcpy (buf, &hdr, sizeof(sr_icmp_t3_hdr_t));
	return buf;
}

uint8_t* build_arp_packet(unsigned short ar_op, unsigned char ar_sha[], uint32_t ar_sip, const unsigned char ar_tha[],
							uint32_t ar_tip) {
	uint8_t* buf;
	struct sr_arp_hdr hdr;
    hdr.ar_hrd = arp_hrd_ethernet;             /* format of hardware address   */
    hdr.ar_pro = ethertype_ip;             /* format of protocol address   */
    hdr.ar_hln = ETHER_ADDR_LEN;             /* length of hardware address   */
    hdr.ar_pln = 4;             /* length of protocol address   */
    hdr.ar_op = ar_op;              /* ARP opcode (command)         */
	memcpy(hdr.ar_sha,ar_sha,ETHER_ADDR_LEN); /* sender hardware address      */
    hdr.ar_sip = ar_sip;             /* sender IP address            */
	memcpy(hdr.ar_tha,ar_tha,ETHER_ADDR_LEN); /* target hardware address      */
    hdr.ar_tip = ar_tip;             /* target IP address            */
	
	buf = (uint8_t*) malloc (sizeof(sr_arp_hdr_t));
	memcpy (buf, &hdr, sizeof(sr_arp_hdr_t));
	return buf;
}


/* Convert raw packet to host byte order 
   buf[IN] - raw packet buffer
   buf[OUT] - packet buffer with byte order converted 
   return - 0 on success, otherwise error code */
RC convert_to_host(uint8_t *buf) {
	sr_ethernet_hdr_t* eth;
	uint8_t* eth_payload;
	
	/* parse ether frame */
	eth = parse_eth_frame(buf, &eth_payload);
	eth->ether_type = ntohs(eth->ether_type);
	/* parse ethernet payload - ip packet */
	if(eth->ether_type == ethertype_ip) {
		sr_ip_hdr_t* ip;
		uint8_t* ip_payload;
		ip = parse_ip_packet(eth_payload, &ip_payload);
		
		/* parse ip payload - icmp */
		if(ip->ip_p == ip_protocol_icmp) {
			sr_icmp_hdr_t* icmp;
			icmp = parse_icmp_packet(ip_payload);
			
			/* icmp packet */
			if(icmp->icmp_type == icmp_type_echo_request) {
				/* icmp->icmp_sum = ntohs(icmp->icmp_sum); */
			}
			/* icmp_t3 packet */
			else {
				sr_icmp_t3_hdr_t* icmp_t3;	
				icmp_t3 = parse_icmp_t3_packet(ip_payload);
				/* icmp_t3->icmp_sum = ntohs(icmp_t3->icmp_sum); */
				icmp_t3->unused = ntohs(icmp_t3->unused);
				icmp_t3->next_mtu = ntohs(icmp_t3->next_mtu);
			}
		}
		
		/* convert ip headers */
		ip->ip_len = ntohs(ip->ip_len);
		ip->ip_id = ntohs(ip->ip_id);
		ip->ip_off = ntohs(ip->ip_off);
		/*ip->ip_sum = ntohs(ip->ip_sum);*/
		/*ip->ip_src = ntohl(ip->ip_src);*/
		/*ip->ip_dst = ntohl(ip->ip_dst);*/
	}
	/* parse ethernet payload - arp packet */
	else if(eth->ether_type == ethertype_arp) {
		sr_arp_hdr_t* arp;
		arp = parse_arp_packet(eth_payload);
		
		arp->ar_hrd = ntohs(arp->ar_hrd);
		arp->ar_pro = ntohs(arp->ar_pro);
		arp->ar_op = ntohs(arp->ar_op);
		/*arp->ar_sip = ntohl(arp->ar_sip);*/
		/*arp->ar_tip = ntohl(arp->ar_tip);*/
	}
	else {
		/* change the ether_type back if there is an error */
		eth->ether_type = htons(eth->ether_type);
		return RC_GENERAL_ERROR;
	}
	
	return 0;
}

/* Convert host-converted packet to network byte order 
   buf[IN] - host packet buffer
   buf[OUT] - raw packet buffer with byte order converted 
   return - 0 on success, otherwise error code */
RC convert_to_network(uint8_t *buf) {
	sr_ethernet_hdr_t* eth;
	uint8_t* eth_payload;
	
	/* parse ether frame */
	eth = parse_eth_frame(buf, &eth_payload);
	/* do not convert ether_type to network byte order yet, 
	   need to use it in host order first */
	/* parse ethernet payload - ip packet */
	if(eth->ether_type == ethertype_ip) {
		convert_ip_to_network(eth_payload);
	}
	/* parse ethernet payload - arp packet */
	else if(eth->ether_type == ethertype_arp) {
		sr_arp_hdr_t* arp;
		arp = parse_arp_packet(eth_payload);
		
		arp->ar_hrd = htons(arp->ar_hrd);
		arp->ar_pro = htons(arp->ar_pro);
		arp->ar_op = htons(arp->ar_op);
		/*arp->ar_sip = htonl(arp->ar_sip);*/
		/*arp->ar_tip = htonl(arp->ar_tip);*/
	}
	else {
		return RC_GENERAL_ERROR;
	}
	
	eth->ether_type = htons(eth->ether_type);
	return 0;
}

void convert_ip_to_network(uint8_t *eth_payload) {
	sr_ip_hdr_t* ip;
	uint8_t* ip_payload;
	ip = parse_ip_packet(eth_payload, &ip_payload);
	
	/* parse ip payload - icmp */
	if(ip->ip_p == ip_protocol_icmp) {
		convert_icmp_to_network(ip_payload);
	}

	/* convert ip headers */
	ip->ip_len = htons(ip->ip_len);
	ip->ip_id = htons(ip->ip_id);
	ip->ip_off = htons(ip->ip_off);
	/*ip->ip_sum = htons(ip->ip_sum);*/
	/*ip->ip_src = htonl(ip->ip_src);*/
	/*ip->ip_dst = htonl(ip->ip_dst);*/
}
void convert_icmp_to_network(uint8_t *ip_payload) {
	sr_icmp_hdr_t* icmp;
	icmp = parse_icmp_packet(ip_payload);
	
	/* icmp packet */
	if(icmp->icmp_type == icmp_type_echo_request) {
		/*icmp->icmp_sum = htons(icmp->icmp_sum);*/
	}
	/* icmp_t3 packet */
	else {
		sr_icmp_t3_hdr_t* icmp_t3;	
		icmp_t3 = parse_icmp_t3_packet(ip_payload);
		/*icmp_t3->icmp_sum = htons(icmp_t3->icmp_sum);*/
		icmp_t3->unused = htons(icmp_t3->unused);
		icmp_t3->next_mtu = htons(icmp_t3->next_mtu);
	}
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