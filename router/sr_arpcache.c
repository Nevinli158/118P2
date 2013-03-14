#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_rt.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
	struct sr_arpreq *req;
	req = sr->cache.requests;
	/*For each entry in sr->cache->requests (linked list of requests)*/
	while(req != NULL){
		if(req->times_sent < 5){
			/*If the request was sent less than 5 times, send the request. (function is such that a request is sent every minute)*/
			uint8_t *arp_pack, *eth_pack;
			struct sr_packet *request_pack = req->packets;
			struct sr_if* iface = sr_get_interface(sr,request_pack->iface);
			unsigned char buf[6]; 
			int i;
			for(i = 0; i < 6; i++){
				buf[i] = 0xff;
			}
			if(iface == 0){ Debug("sr_arpcache_sweepreqs<5: get_interface returned null"); }
			arp_pack = build_arp_packet(arp_op_request, iface->addr, iface->ip, BCAST_MAC_ADDR, req->ip);
			eth_pack = build_eth_frame((uint8_t*)BCAST_MAC_ADDR,iface->addr,ethertype_arp, arp_pack, sizeof(struct sr_arp_hdr));
			sr_send_packet(sr, eth_pack, sizeof(struct sr_arp_hdr)+sizeof(struct sr_ethernet_hdr), request_pack->iface);
			req->times_sent++;
			
			free(arp_pack);
			free(eth_pack);
			req = req->next;
		} else { /*If the request was sent 5 times: */
			struct sr_packet *request_pack = req->packets;
			struct sr_arpreq *temp = req;
			/*For each packet depending on this ARP (sr_packet)*/
			while(request_pack != NULL){
				uint8_t* failed_ip_pack = NULL;/*The client's packet that could not be sent*/
				struct sr_ethernet_hdr *failed_pack_eth_hdr = NULL; 
				struct sr_ip_hdr* failed_pack_ip_hdr = NULL;
				uint8_t* failed_ip_payload = NULL;
				uint8_t* icmp_pack, *ip_pack, *eth_pack;
				struct sr_arpentry *client_mac;
				char* char_iface = NULL;
				struct sr_if* iface; 
				int ip_payload_len = sizeof(struct sr_icmp_t3_hdr);
				int eth_payload_len = ip_payload_len + sizeof(struct sr_ip_hdr);
				unsigned int eth_pack_len = eth_payload_len + sizeof(struct sr_ethernet_hdr); /* */
				
				failed_pack_eth_hdr = parse_eth_frame(request_pack->buf, &failed_ip_pack);
				failed_pack_ip_hdr = parse_ip_packet(failed_ip_pack, &failed_ip_payload);
				if(sr_prefix_match(sr, failed_pack_ip_hdr->ip_src, char_iface) == false){
					Debug("Prefix matching failed");
					request_pack = request_pack->next;
					continue;
				}
				
				iface = sr_get_interface(sr, char_iface);
				icmp_pack = build_icmp_t3_packet(3, 1, failed_ip_pack);
				ip_pack = build_ip_packet(0, 0, ip_protocol_icmp, iface->ip, failed_pack_ip_hdr->ip_src, icmp_pack, ip_payload_len);
									
				/*Look at ARP cache for the client's MAC */					
				client_mac =  sr_arpcache_lookup( &(sr->cache), failed_pack_ip_hdr->ip_src);
				if(client_mac == NULL || client_mac->valid == 0){ /* MAC wasn't found, add the packet to the ARP queue */
					eth_pack = build_eth_frame(0,iface->addr,ethertype_ip, ip_pack, eth_payload_len);
					sr_arpcache_queuereq( &(sr->cache), failed_pack_ip_hdr->ip_src, eth_pack, eth_pack_len, iface->name);
				} else { /*MAC was found, send the packet off */
					eth_pack = build_eth_frame(client_mac->mac,iface->addr,ethertype_ip, ip_pack, eth_payload_len);
					sr_send_packet(sr, eth_pack, eth_pack_len , request_pack->iface);
				}
				
				free(icmp_pack);
				free(ip_pack);
				free(eth_pack);

				request_pack = request_pack->next;
			}
			req = req->next;
			/*remove the request from the queue*/
			sr_arpreq_destroy(&(sr->cache), temp);
		}
	}
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

