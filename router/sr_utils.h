/*
 *  Copyright (c) 2009 Roger Liao <rogliao@cs.stanford.edu>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef SR_UTILS_H
#define SR_UTILS_H

uint16_t cksum(const void *_data, int len);

uint16_t ethertype(uint8_t *buf);
uint8_t ip_protocol(uint8_t *buf);

/* Packet functions defined in sr_packets.c */
uint8_t* build_eth_frame(sr_ethernet_hdr_t *eth_hdr, uint8_t *data, int datalen);
uint8_t* build_ip_packet(sr_ip_hdr_t *ip_hdr, uint8_t *data, int datalen);
uint8_t* build_icmp_packet(sr_icmp_hdr_t *icmp_hdr);
uint8_t* build_icmp_t3_packet(sr_icmp_t3_hdr_t *icmp_t3_hdr);
uint8_t* build_arp_packet(sr_arp_hdr_t *arp_hdr);


sr_ethernet_hdr_t* parse_eth_frame(uint8_t *buf, uint8_t *payload);
sr_ip_hdr_t* parse_ip_packet(uint8_t *buf, uint8_t *payload);
sr_icmp_hdr_t* parse_icmp_packet(uint8_t *buf);
sr_icmp_t3_hdr_t* parse_icmp_t3_packet(uint8_t *buf);
sr_arp_hdr_t* parse_arp_packet(uint8_t *buf);

/*init functions are defined in sr_init_header.c */
struct sr_icmp_hdr* init_sr_icmp_hdr(uint8_t icmp_type, uint8_t icmp_code, uint16_t icmp_sum);
struct sr_icmp_t3_hdr* init_sr_icmp_t3_hdr(uint8_t icmp_type, uint8_t icmp_code, uint8_t* ip_packet);
struct sr_ip_hdr* init_sr_ip_hdr(unsigned int ip_hl, unsigned int ip_v, uint8_t ip_tos, uint16_t ip_len,
    uint16_t ip_id, uint16_t ip_off, uint8_t ip_ttl, uint8_t ip_p, uint16_t ip_sum, uint32_t ip_src, 
	uint32_t ip_dst);
struct sr_ethernet_hdr* init_sr_ethernet_hdr(uint8_t ether_dhost[], uint8_t ether_shost[], uint16_t ether_type);
struct sr_arp_hdr* init_sr_arp_hdr(unsigned short ar_hrd, unsigned short ar_pro, unsigned char ar_hln,
	unsigned char ar_pln, unsigned short ar_op, unsigned char ar_sha[], uint32_t ar_sip, unsigned char ar_tha[],
    uint32_t ar_tip);
	
void print_addr_eth(uint8_t *addr);
void print_addr_ip(struct in_addr address);
void print_addr_ip_int(uint32_t ip);

void print_hdr_eth(uint8_t *buf);
void print_hdr_ip(uint8_t *buf);
void print_hdr_icmp(uint8_t *buf);
void print_hdr_arp(uint8_t *buf);

/* prints all headers, starting from eth */
void print_hdrs(uint8_t *buf, uint32_t length);

#endif /* -- SR_UTILS_H -- */
