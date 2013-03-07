#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_router.h"


struct sr_icmp_hdr* init_sr_icmp_hdr(uint8_t icmp_type, uint8_t icmp_code, uint16_t icmp_sum){
	struct sr_icmp_hdr* hdr = malloc(sizeof(struct sr_icmp_hdr));
	hdr->icmp_type = icmp_type;
	hdr->icmp_code = icmp_code;
	hdr->icmp_sum = icmp_sum;
	return hdr;
}

struct sr_icmp_t3_hdr* init_sr_icmp_t3_hdr(uint8_t icmp_type, uint8_t icmp_code, uint8_t* failed_ip_packet){
	struct sr_icmp_t3_hdr* hdr = malloc(sizeof(struct sr_icmp_t3_hdr));
	hdr->icmp_type = icmp_type;
	hdr->icmp_code = icmp_code;
	hdr->icmp_sum = 0;
	hdr->unused = 0;
	hdr->next_mtu = 0; /*only used for code 4, which is out of scope of this assignment. */
	if(sizeof(struct sr_ip_hdr)+8 != ICMP_DATA_SIZE){
		Debug("init_sr_icmp_t3_hdr: sizeof(struct sr_ip_hdr)+8 != ICMP_DATA_SIZE");
	}
	memcpy(hdr->data,failed_ip_packet,sizeof(struct sr_ip_hdr));/*Data has IP header + 1st 8 bytes of payload */
	memcpy((hdr->data)+sizeof(struct sr_ip_hdr),failed_ip_packet,8);
	hdr->icmp_sum = cksum((void*)hdr, sizeof(struct sr_icmp_t3_hdr));
	return hdr;
}

struct sr_ip_hdr* init_sr_ip_hdr(uint16_t ip_len,
    uint16_t ip_id, uint16_t ip_off, uint8_t ip_p, uint32_t ip_src, uint32_t ip_dst){
	struct sr_ip_hdr* hdr = malloc(sizeof(struct sr_ip_hdr));
    hdr->ip_hl = 5;		/* header length */
    hdr->ip_v = 4;		/* version */
    hdr->ip_tos = 0;			/* type of service */
    hdr->ip_len = ip_len;			/* total length */
    hdr->ip_id = ip_id;			/* identification */
    hdr->ip_off = ip_off;			/* fragment offset field */
    hdr->ip_ttl = 64;			/* time to live */
    hdr->ip_p = ip_p;			/* protocol */
    hdr->ip_sum = 0;			/* checksum */
    hdr->ip_src = ip_src;
	hdr->ip_dst = ip_dst;	/* source and dest address */
	hdr->ip_sum = cksum((void*)hdr, sizeof(struct sr_ip_hdr));
	return hdr;
}

struct sr_ethernet_hdr* init_sr_ethernet_hdr(uint8_t  ether_dhost[], uint8_t ether_shost[], uint16_t ether_type){
	struct sr_ethernet_hdr* hdr = malloc(sizeof(struct sr_ethernet_hdr));
	memcpy(hdr->ether_dhost,ether_dhost,ETHER_ADDR_LEN); /* destination ethernet address */
	memcpy(hdr->ether_shost,ether_shost,ETHER_ADDR_LEN); /* source ethernet address */
    hdr->ether_type = ether_type;                     /* packet type ID */
	return hdr;
}

struct sr_arp_hdr* init_sr_arp_hdr(unsigned short ar_hrd, unsigned short ar_pro, unsigned char ar_hln,
	unsigned char ar_pln, unsigned short ar_op, unsigned char ar_sha[], uint32_t ar_sip, unsigned char ar_tha[ETHER_ADDR_LEN],
    uint32_t ar_tip){
	struct sr_arp_hdr* hdr = malloc(sizeof(struct sr_arp_hdr));
    hdr->ar_hrd = ar_hrd;             /* format of hardware address   */
    hdr->ar_pro = ar_pro;             /* format of protocol address   */
    hdr->ar_hln = ar_hln;             /* length of hardware address   */
    hdr->ar_pln = ar_pln;             /* length of protocol address   */
    hdr->ar_op = ar_op;              /* ARP opcode (command)         */
	memcpy(hdr->ar_sha,ar_sha,ETHER_ADDR_LEN); /* sender hardware address      */
    hdr->ar_sip = ar_sip;             /* sender IP address            */
	memcpy(hdr->ar_tha,ar_tha,ETHER_ADDR_LEN); /* target hardware address      */
    hdr->ar_tip = ar_tip;             /* target IP address            */
	return hdr;
}
