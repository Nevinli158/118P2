#ifndef SR_HEADERS_H
#define SR_HEADERS_H

#include "sr_protocol.h"

/* length of the ethernet frame checksum */
const unsigned int FCS_SIZE = 4;
const unsigned int MIN_ETH_PAYLOAD = 46;

const unsigned int MIN_ICMP = sizeof(sr_icmp_hdr_t);
const unsigned int MIN_ICMP_T3 = sizeof(sr_icmp_t3_hdr_t);
const unsigned int MIN_IP = sizeof(sr_ip_hdr_t);
const unsigned int MIN_ETH = sizeof(sr_ethernet_hdr_t) + 46 + 4;
const unsigned int MIN_ARP = sizeof(sr_arp_hdr_t);


#endif /* -- SR_HEADERS_H -- */