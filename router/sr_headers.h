#ifndef SR_HEADERS_H
#define SR_HEADERS_H

#include "sr_protocol.h"

typedef int RC;
const int RC_INSERTED_INTO_ARP_CACHE = -1001;
const int RC_CHKSUM_FAILED = -1002;
const int RC_PACKET_LEN_TOO_SMALL = -1003;
const int RC_GENERAL_ERROR = -1004;

/* length of the ethernet frame checksum */
const unsigned int FCS_SIZE = 4;

const unsigned int MIN_ICMP = sizeof(sr_icmp_hdr_t);
const unsigned int MIN_ICMP_T3 = sizeof(sr_icmp_t3_hdr_t);
const unsigned int MIN_IP = sizeof(sr_ip_hdr_t);
const unsigned int MIN_ETH = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + 4;
const unsigned int MIN_ARP = sizeof(sr_arp_hdr_t);


#endif /* -- SR_HEADERS_H -- */