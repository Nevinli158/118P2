/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  struct sr_ethernet_hdr* eth_frame = NULL;
  uint8_t* ether_payload = NULL;
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  
  /* function for comparing checksum before parsing packet */
  if(verify_eth_cksum(packet, len) == false){
	Debug("Ethernet checksum failed. Dropping packet.");
	return;
  }
  eth_frame = parse_eth_frame(packet, ether_payload);
  if(eth_frame->ether_type ==  ethertype_ip){  /*IP*/

	uint8_t* ip_payload = NULL;
	struct sr_ip_hdr* ip_hdr = NULL;
	/* Subtract out the checksum stuff too? */
	int ip_pack_len = len - sizeof(struct sr_ethernet_hdr) - 2;

	if(verify_ip_cksum(ether_payload, ip_pack_len) == false){
		Debug("IP checksum failed. Dropping packet.");
		return;
    }
	
	ip_hdr = parse_ip_packet(ether_payload, ip_payload);
	ip_hdr->ip_ttl--; 
	
	/* If the packet is destined to the router or if TTL hit 0:
		all cases where router needs to build and return an ICMP packet*/	
	if(ip_hdr->ip_ttl <= 0
		|| is_router_ip(sr, ip_hdr->ip_src)){ 
		uint8_t* icmp_pack, *ip_pack, *eth_pack;
		int ip_payload_len;
		int eth_payload_len; 
		unsigned int eth_pack_len; 
		struct sr_if* interface_if = sr_get_interface(sr, interface);
		struct sr_arpentry *client_mac;
		if(interface_if == 0){Debug("HandlePacket interface not found.");}
		/* Build the ICMP packet depending on the circumstances */
		if(ip_hdr->ip_ttl <= 0){ /* If the packet is out of hops */
			/* Time exceeded */
			icmp_pack = build_icmp_packet(11,0);
			ip_payload_len = sizeof(struct sr_icmp_hdr);
		} else if(ip_hdr->ip_p != ip_protocol_icmp){ /* Received a non ICMP packet destined for a router interface */
			/* Port unreachable */
			icmp_pack = build_icmp_t3_packet(3,3, ip_payload);
			ip_payload_len = sizeof(struct sr_icmp_t3_hdr);
		} else { /* Received an ICMP packet destined for a router interface */
			sr_icmp_hdr_t* icmp_hdr = parse_icmp_packet(ip_payload);
			if(icmp_hdr->icmp_type == icmp_type_echo_request){
				/* Echo reply */
				icmp_pack = build_icmp_packet(0,0);
				ip_payload_len = sizeof(struct sr_icmp_t3_hdr);			
			} else {/* what do if received ICMP packet with type not echo request. */
				return;
			
			}
		}
		eth_payload_len = ip_payload_len + sizeof(struct sr_ip_hdr);
		eth_pack_len = eth_payload_len + sizeof(struct sr_ethernet_hdr) + 2; 
		ip_pack = build_ip_packet(0, 0, ip_protocol_icmp, interface_if->ip, ip_hdr->ip_src, icmp_pack, ip_payload_len);
		
		/*Look at ARP cache for the client's MAC */					
		client_mac =  sr_arpcache_lookup( &(sr->cache), ip_hdr->ip_src);
		if(client_mac == NULL || client_mac->valid == 0){ /* MAC wasn't found, add the packet to the ARP queue */
			eth_pack = build_eth_frame(0,interface_if->addr,ethertype_ip, ip_pack, eth_payload_len);
			struct sr_arpreq *arpreq = 
			sr_arpcache_queuereq( &(sr->cache), ip_hdr->ip_src, eth_pack, eth_pack_len, interface);
			
			if(arpreq != 0){free(arpreq);}
		} else { /*MAC was found, send the packet off back to original client */
			char outgoing[sr_IFACE_NAMELEN];
			struct sr_if* outgoing_if = NULL;
			if(sr_prefix_match(sr, ip_hdr->ip_src, outgoing)){
				outgoing_if = sr_get_interface(sr, outgoing);
				if(outgoing_if == 0){Debug("HandlePacket: outgoing if = 0");}
				eth_pack = build_eth_frame(client_mac->mac,outgoing_if->addr,ethertype_ip, ip_pack, eth_payload_len);
				sr_send_packet(sr, eth_pack, eth_pack_len , outgoing);
			} else {
				Debug("No prefix match found: dropping packet");
			}
			
		}
	} else { /* Packet is not destined to the router */
	
	}
	/* 
	*/
  } else if(eth_frame->ether_type ==  ethertype_arp){/*ARP*/
	struct sr_arp_hdr* arp_hdr = parse_arp_packet(ether_payload);
	if(arp_hdr->ar_op == arp_op_request){
		
	} else if(arp_hdr->ar_op == arp_op_reply){
	
	} else {
		
	}
  }

}/* end sr_ForwardPacket */

