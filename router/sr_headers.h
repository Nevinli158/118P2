#ifndef SR_HEADERS_H
#define SR_HEADERS_H

#include "sr_protocol.h"

typedef int RC;
static const int RC_INSERTED_INTO_ARP_CACHE = -1001;
static const int RC_CHKSUM_FAILED = -1002;
static const int RC_PACKET_LEN_TOO_SMALL = -1003;
static const int RC_GENERAL_ERROR = -1004;
static const int RC_ARP_NOT_DESTINED_TO_ROUTER = -1005;

static const unsigned int MIN_ICMP = sizeof(sr_icmp_hdr_t);
static const unsigned int MIN_ICMP_T3 = sizeof(sr_icmp_t3_hdr_t);
static const unsigned int MIN_IP = sizeof(sr_ip_hdr_t);
static const unsigned int MIN_ETH = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + 4;
static const unsigned int MIN_ARP = sizeof(sr_arp_hdr_t);


#endif /* -- SR_HEADERS_H -- */