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
#include <string.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_headers.h"

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
        char* interface/* lent */
		)
{
  struct sr_ethernet_hdr* in_eth_pack = NULL;
  uint8_t* in_ether_payload = NULL;
	uint32_t out_dest_ip = 0;
	 uint8_t* out_eth_payload = NULL; 
	int out_eth_payload_len = 0; 
	struct sr_arpentry *out_client_mac;
	unsigned int out_eth_pack_len; 
	unsigned int out_eth_type; 
	uint8_t *out_eth_pack = NULL;

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  convert_to_host(packet);
  /* function for comparing checksum before parsing packet */
 
  /*Construct the outgoing ethernet payload */		
  
  in_eth_pack = parse_eth_frame(packet, &in_ether_payload);
  if(in_eth_pack->ether_type == ethertype_ip){  /*IP*/
	int ip_pack_len = len - sizeof(struct sr_ethernet_hdr); 	
	int rc = sr_process_ip_payload(sr, interface, in_ether_payload, ip_pack_len, &out_eth_payload, &out_eth_payload_len, &out_dest_ip);
	if(rc != 0){
		return;
	}	
	out_eth_type = ethertype_ip;
	
  } else if(in_eth_pack->ether_type ==  ethertype_arp){/*ARP*/
	int arp_pack_len = len - sizeof(struct sr_ethernet_hdr);
	int rc = sr_process_arp_payload(sr, in_ether_payload, arp_pack_len, &out_eth_payload, &out_dest_ip);
	if(rc == RC_INSERTED_INTO_ARP_CACHE){
		return;
	} else if(rc == RC_ARP_NOT_DESTINED_TO_ROUTER){
		Debug("Dropping ARP not destined for router.");
		return;
	} else if (rc == RC_GENERAL_ERROR){
		Debug("Dropping ARP with invalid op.");
		return;		
	}
	out_eth_type = ethertype_arp;
	out_eth_payload_len = sizeof(struct sr_arp_hdr);
  }
  
	/*Construct the outgoing ethernet frame and send it off */			
	
  	out_eth_pack_len = out_eth_payload_len + sizeof(struct sr_ethernet_hdr); 	
	/*Look at ARP cache for the client's MAC */					
	out_client_mac =  sr_arpcache_lookup( &(sr->cache), out_dest_ip);
	if(out_client_mac == NULL || out_client_mac->valid == 0){ /* MAC wasn't found, add the packet to the ARP queue */
		uint8_t ether_dhost = 0;
		struct sr_if* interface_if = sr_get_interface(sr, interface);	
		out_eth_pack = build_eth_frame(&ether_dhost,interface_if->addr,out_eth_type, out_eth_payload, out_eth_payload_len);
		sr_arpcache_queuereq( &(sr->cache), out_dest_ip, out_eth_pack, out_eth_pack_len, interface);
		
	} else { /*MAC was found, send the packet off back to original client */
		char outgoing[sr_IFACE_NAMELEN];
		struct sr_if* outgoing_if = NULL;
		if(sr_prefix_match(sr, out_dest_ip, outgoing)){
			outgoing_if = sr_get_interface(sr, outgoing);
			if(outgoing_if == 0){Debug("HandlePacket: outgoing if = 0");}
			out_eth_pack = build_eth_frame(out_client_mac->mac,outgoing_if->addr,out_eth_type, out_eth_payload, out_eth_payload_len);
			sr_send_packet(sr, out_eth_pack, out_eth_pack_len, outgoing);
		} else {
			Debug("No prefix match found: dropping packet");
		}
	}
	
	if(out_eth_payload != NULL){free(out_eth_payload);}
	if(out_eth_pack != NULL){free(out_eth_pack);}

}/* end sr_ForwardPacket */


/**
	Processes an incoming IP packet, and generates a response IP packet based on the payload.
	Returns error code if the incoming IP packet should be dropped.
	@param sr[IN]
	@param interface[IN] - borrowed
	@param in_ip_packet[IN] - The IP packet that the response is based off of
	@param in_ip_packet_len[IN] - Length of the incoming IP packet.
	@param out_ip_packet[OUT] - Takes in an empty pointer, and sets it to the new outgoing packet that needs to be freed.
	@param out_ip_packet_len[OUT] - Length of the outgoing IP packet
	@param out_dest_ip[OUT] - Destination IP of the outgoing IP packet. More for convenience so you don't need to parse out_ip_packet
*/
int sr_process_ip_payload(struct sr_instance* sr, char* interface, uint8_t* in_ip_packet, int in_ip_packet_len,
							uint8_t** out_ip_packet, int* out_ip_packet_len, uint32_t* out_dest_ip){
	uint8_t* in_ip_payload = NULL;
	struct sr_ip_hdr* in_ip_hdr = NULL;
	int out_ip_payload_len;
	struct sr_if* interface_if = sr_get_interface(sr, interface);	
	uint32_t in_ip_hdr_ip_dst = 0;

	/* Subtract out the checksum stuff too? */

	if(verify_ip_cksum(in_ip_packet, in_ip_packet_len) == false){
		Debug("IP checksum failed. Dropping packet. \n");
		return RC_CHKSUM_FAILED;
    }
	
	in_ip_hdr = parse_ip_packet(in_ip_packet, &in_ip_payload);

	in_ip_hdr_ip_dst = in_ip_hdr->ip_dst;
	/* If the packet is destined to the router or if TTL would hit 0:
		all cases where router needs to build and return an ICMP packet*/	
	if(in_ip_hdr->ip_ttl <= 1
		|| is_router_ip(sr, in_ip_hdr_ip_dst)){ 
		uint8_t* icmp_pack = NULL;
		uint32_t out_ip_packet_src_ip;
		
		if(interface_if == 0){Debug("HandlePacket interface not found.");}
		/* Build the ICMP packet depending on the circumstances */
		if(in_ip_hdr->ip_ttl <= 0){ /* If the packet is out of hops */
			/* Time exceeded */
			printf("*** -> IP Packet, out of hops \n");
			icmp_pack = build_icmp_packet(11,0);
			out_ip_payload_len = sizeof(struct sr_icmp_hdr);
			if(is_router_ip(sr, in_ip_hdr_ip_dst)){ 
				/* If destined to a router ip, reply from that router ip */
				out_ip_packet_src_ip = in_ip_hdr_ip_dst;
			} else {
				/* If destined to another ip, reply from interface that the packet came in */
				out_ip_packet_src_ip = interface_if->ip;
			}
		} else if(in_ip_hdr->ip_p != ip_protocol_icmp){ /* Received a non ICMP packet destined for a router interface */
			/* Port unreachable */
			printf("*** -> IP Packet, TCP/UDP Payload \n");
			icmp_pack = build_icmp_t3_packet(3,3, in_ip_payload);
			out_ip_payload_len = sizeof(struct sr_icmp_t3_hdr);
			out_ip_packet_src_ip = in_ip_hdr_ip_dst;
		} else { /* Received an ICMP packet destined for a router interface */
			printf("*** -> IP Packet, ICMP destined for router \n");
			sr_icmp_hdr_t* icmp_hdr = parse_icmp_packet(in_ip_payload);
			if(icmp_hdr->icmp_type == icmp_type_echo_request){
				uint8_t* echo_reply_payload = NULL;
				icmp_hdr = parse_icmp_t0_packet(in_ip_payload, &echo_reply_payload);
				int icmp_len = in_ip_packet_len - sizeof(sr_ip_hdr_t);
				int icmp_payload_len =  icmp_len - sizeof(struct sr_icmp_hdr);
				if(verify_icmp_cksum(in_ip_payload, icmp_len) == false){
					Debug("ICMP checksum failed. Dropping packet. \n");
					return RC_CHKSUM_FAILED;
				}
				/* Echo reply */
				
				icmp_pack = build_icmp_t0_packet(echo_reply_payload,icmp_payload_len);

				out_ip_payload_len = sizeof(struct sr_icmp_hdr) + icmp_payload_len;	
				out_ip_packet_src_ip = in_ip_hdr_ip_dst;
			} else {/* what do if received ICMP packet with type not echo request. */
				return RC_GENERAL_ERROR;
			}
		}
		*out_ip_packet = build_ip_packet(0, 0, ip_protocol_icmp, out_ip_packet_src_ip, in_ip_hdr->ip_src, icmp_pack, out_ip_payload_len);
		*out_dest_ip = in_ip_hdr->ip_src;
		
		if(icmp_pack != NULL){free(icmp_pack);}
	} else { /* Packet is not destined to the router */
		printf("*** -> IP Packet not destined for router \n");
		*out_ip_packet = malloc(in_ip_packet_len);
		memcpy(*out_ip_packet, in_ip_packet, in_ip_packet_len);
		*out_dest_ip = in_ip_hdr_ip_dst;
		out_ip_payload_len = in_ip_packet_len - sizeof(struct sr_ip_hdr);
	}
	*out_ip_packet_len = out_ip_payload_len + sizeof(struct sr_ip_hdr);
	return 0;
}


/**

	Processes an incoming ARP packet, and generates a response ARP packet if it was a request from the router.
	If it was a reply, then it adds it to the ARP cache and returns a code signifying that it was a reponse.
	@param sr[IN]
	@param interface[IN] - borrowed
	@param in_ip_packet[IN] - The IP packet that the response is based off of
	@param in_ip_packet_len[IN] - Length of the incoming IP packet.
	@param out_ip_packet[OUT] - Takes in an empty pointer, and sets it to the new outgoing packet that needs to be freed.
	@param out_ip_packet_len[OUT] - Length of the outgoing IP packet
	@param out_dest_ip[OUT] - Destination IP of the outgoing IP packet. More for convenience so you don't need to parse out_ip_packet
	@return 0 if a packet was generated due to a request.
			error code
*/
int sr_process_arp_payload(struct sr_instance* sr, uint8_t* in_arp_packet, int in_arp_packet_len, 
							uint8_t** out_arp_packet, uint32_t* out_dest_ip){
	struct sr_arp_hdr* arp_hdr = parse_arp_packet(in_arp_packet);
	/*If the incoming packet is an ARP packet that we made. This happens when the packet is queued up waiting for the dest
	IP to be found, and the ARP reply with the dest ip has been found.*/
	if (is_router_ip(sr, arp_hdr->ar_sip)){
			/*Just copy the original ARP packet*/
			*out_arp_packet = build_arp_packet(arp_hdr->ar_op, arp_hdr->ar_sha, arp_hdr->ar_sip, arp_hdr->ar_tha,
							arp_hdr->ar_tip);
			*out_dest_ip = arp_hdr->ar_tip;
			return 0;
	}
	/*If the incoming packet is from another source.*/
	if(arp_hdr->ar_op == arp_op_request){ /*Reply to the request*/
		unsigned char* router_mac = (unsigned char*)is_router_ip(sr, arp_hdr->ar_tip);
		printf("*** -> ARP Request Packet \n");
		if(router_mac != NULL){/*Only respond to requests destined to the router.*/
			*out_arp_packet = build_arp_packet(arp_op_reply, router_mac, arp_hdr->ar_tip, arp_hdr->ar_sha,
							arp_hdr->ar_sip);
			*out_dest_ip = arp_hdr->ar_sip;
			return 0;
		} else {
			return RC_ARP_NOT_DESTINED_TO_ROUTER;
		}
	} else if(arp_hdr->ar_op == arp_op_reply){/*Insert the reply into the cache*/
		printf("*** -> ARP Reply Packet \n");
		if(is_router_ip(sr, arp_hdr->ar_tip)){/*Only cache replies destined to the router.*/
			struct sr_arpreq *requests = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
			printf("*** -> ARP Reply Packet: inserting sip:%x, sha:",arp_hdr->ar_sip);
			print_addr_eth(arp_hdr->ar_sha);
			printf("\n");
			struct sr_packet *next_packet = requests->packets;
			while(next_packet != NULL){
				Debug("Next Received Packet is an old, queued up packet: \n");
				
				if(convert_to_network(next_packet->buf) != 0){
					Debug("Conversion failed.\n");
				}
				print_hdrs(next_packet->buf,next_packet->len);
				sr_handlepacket(sr, next_packet->buf, next_packet->len, next_packet->iface);

				next_packet = next_packet->next;
			}
			
			free(requests);
			
			return RC_INSERTED_INTO_ARP_CACHE;
		 
		} else {
			return RC_ARP_NOT_DESTINED_TO_ROUTER;
		}
	} 
	
	return RC_GENERAL_ERROR;
				
}






