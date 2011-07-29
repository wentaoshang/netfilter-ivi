/*
 * ivi_xmit.c :
 *  IVI Packet Transmission Kernel Module
 * 
 * by haoyu@cernet.edu.cn 2008.10.22
 *
 * Changes:
 *	Wentao Shang	:	Remove multicast functionality and implement skbuff re-enter.
 *	Wentao Shang	:	Simplified prefix matching and address translation, v4network and v6prefix are now hard coded.
 *	Wentao Shang	:	Add NAT44-PT support.
 *	Wentao Shang	:	Add ICMP translation support.
 *	Wentao Shang	:	IPv6 prefix length is configurable now.
 *	Wentao Shang	:	Modified to host-based IVI. Remove NAT44 functionality.
 */

#include "ivi_xmit.h"

static __inline int mc_v4_addr(const unsigned int *addr) {
	return ((ntohl(*addr) & 0xe0000000) == 0xe0000000);
}
	          
static __inline int mc_v6_addr(const struct in6_addr *addr) {
	return (addr->s6_addr[0] == 0xff);
}

// v4 address allocated to the host.
__be32 v4addr = 0x01010101;  // "1.1.1.1" in host byte order
EXPORT_SYMBOL(v4addr);

__be32 v4mask = 0xffffff00;  // "/24" prefix length for the v4 address
EXPORT_SYMBOL(v4mask);

// v6 ivi prefix
__u8 v6prefix[16] = { 0x20, 0x01, 0x0d, 0xa8, 0x01, 0x23, 0x04, 0x56 };  // "2001:da8:123:456::" in network byte order
EXPORT_SYMBOL(v6prefix);

__be32 v6prefixlen = 8;  // "/64" ivi prefix length in bytes (8)
EXPORT_SYMBOL(v6prefixlen);

__u8 addr_fmt = 0;  // ivi translated address format
EXPORT_SYMBOL(addr_fmt);

/*
 * Returns whether the v4 address belongs to the same network with the host.
 */
static __inline int addr_in_v4network(const unsigned int *addr) {
	return ((ntohl(*addr) & v4mask) == (v4addr & v4mask));
}

/*
 * Returns whether the v4 address is the host v4 address.
 */
static __inline int addr_is_v4host(const unsigned int *addr) {
	return (ntohl(*addr) == v4addr);
}

/*
 * Returns whether the v6 address belongs to the same network which the host's v4 network is mapped into.
 */
int addr_in_v6network(const struct in6_addr *addr) {
	__be32 embed = 0;
	int i, ret = 1;
	
	for (i = 0; i < v6prefixlen; i++) {
		if (addr->s6_addr[i] != v6prefix[i]) {
			ret = 0;
			break;
		}
	}
	
	if (ret == 0) {
		return ret;
	}
	
	embed |= ((unsigned int)addr->s6_addr[v6prefixlen]) << 24;
	embed |= ((unsigned int)addr->s6_addr[v6prefixlen + 1]) << 16;
	embed |= ((unsigned int)addr->s6_addr[v6prefixlen + 2]) << 8;
	embed |= ((unsigned int)addr->s6_addr[v6prefixlen + 3]);
	
	return ((embed & v4mask) == (v4addr & v4mask));
}

/*
 * Returns whether the v6 address is the host's mapped ivi address
 */
int addr_is_v6host(const struct in6_addr *addr) {
	__be32 embed = 0;
	int i, ret = 1;
	
	for (i = 0; i < v6prefixlen; i++) {
		if (addr->s6_addr[i] != v6prefix[i]) {
			ret = 0;
			break;
		}
	}
	
	if (ret == 0) {
		return ret;
	}
	
	embed |= ((unsigned int)addr->s6_addr[v6prefixlen]) << 24;
	embed |= ((unsigned int)addr->s6_addr[v6prefixlen + 1]) << 16;
	embed |= ((unsigned int)addr->s6_addr[v6prefixlen + 2]) << 8;
	embed |= ((unsigned int)addr->s6_addr[v6prefixlen + 3]);
	
	return (embed == v4addr);
}

int ipaddr_4to6(unsigned int *v4addr, struct in6_addr *v6addr, __u8 fmt) {
	unsigned int addr = ntohl(*v4addr);
	
	memset(v6addr, 0, sizeof(struct in6_addr));
	memcpy(v6addr->s6_addr, v6prefix, v6prefixlen);
	v6addr->s6_addr[v6prefixlen] = (unsigned char)(addr >> 24);
	v6addr->s6_addr[v6prefixlen + 1] = (unsigned char)((addr >> 16) & 0xff);
	v6addr->s6_addr[v6prefixlen + 2] = (unsigned char)((addr >> 8) & 0xff);
	v6addr->s6_addr[v6prefixlen + 3] = (unsigned char)(addr & 0xff);
	
	if (fmt == ADDR_FMT_POSTFIX) {
		v6addr->s6_addr16[6] = htons(ratio);
		v6addr->s6_addr16[7] = htons(offset);
	} else if (fmt == ADDR_FMT_SUFFIX) {
		v6addr->s6_addr[v6prefixlen + 4] = (suffix >> 8) & 0xff;
		v6addr->s6_addr[v6prefixlen + 5] = suffix & 0xff;
	}
	
	return 0;  // This function always succeed.
}

int ipaddr_6to4(struct in6_addr *v6addr, unsigned int *v4addr) {
	__be32 addr = 0;
	
	addr |= ((unsigned int)v6addr->s6_addr[v6prefixlen]) << 24;
	addr |= ((unsigned int)v6addr->s6_addr[v6prefixlen + 1]) << 16;
	addr |= ((unsigned int)v6addr->s6_addr[v6prefixlen + 2]) << 8;
	addr |= ((unsigned int)v6addr->s6_addr[v6prefixlen + 3]);
	*v4addr = htonl(addr);
	
	return 0;  // This function always succeed.
}

int ivi_v4v6_xmit(struct sk_buff *skb) {
	int err;
	struct sk_buff *newskb;
	struct iphdr *ip4h;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;
	struct icmp6hdr *icmp6h;
	__u8 *payload;
	int hlen, plen;

	/*
	 * We are not always in process context. For example, TCP retransmission is in interrupt context.
	 */
	gfp_t alloc_prio = in_softirq() ? GFP_ATOMIC : GFP_KERNEL;
	
	//struct rt6_info *rt;
	
	ip4h = ip_hdr(skb);
	if (mc_v4_addr(&(ip4h->daddr))) {
		// By pass multicast packet
		printk(KERN_DEBUG "ivi_v4v6_xmit: by pass ipv4 multicast packet.\n");
		return -EINVAL;
	}
	
	if (unlikely(addr_is_v4host(&(ip4h->saddr)) == 0)) {
		// Do not translate packets that are not sent by the local host, return 0 to drop packet.
		printk(KERN_DEBUG "ivi_v4v6_xmit: drop IPv4 packet that is not sent by the local host.\n");
		return 0;
	}

	if (unlikely(addr_is_v4host(&(ip4h->daddr)))) {
		// Do not translate ipv4 packets that are toward the host (which should not be possible.).
		printk(KERN_ERR "ivi_v4v6_xmit: by pass IPv4 packet heading toward the host.\n");
		return -EINVAL;  // Just accept.
	}
/*
	if (addr_in_v4network(&(ip4h->daddr))) {
		// Do not translate ipv4 packets that are toward the v4 network where the host is located.
		printk(KERN_DEBUG "ivi_v6v4_xmit: IPv4 packet to the host network bypassed on the sending routine.\n");
		return -EINVAL;  // Just accept.
	}
*/
	if (addr_fmt != ADDR_FMT_NONE) {
		__be16 newp;
		
		payload = (__u8 *)(ip4h) + (ip4h->ihl << 2);
		switch (ip4h->protocol) {
			case IPPROTO_TCP:
				tcph = (struct tcphdr *)payload;
				
				if (get_outflow_map_port(ntohs(tcph->source), &tcp_list, &newp) == -1) {
					printk(KERN_ERR "ivi_v4v6_xmit: fail to perform ivi mapping for port %d (TCP).\n", ntohs(tcph->source));
					// Just let the packet pass with original address.
				} else {
					tcph->source = htons(newp);
				}
				
				break;
			
			case IPPROTO_UDP:
				udph = (struct udphdr *)payload;
				
				if (get_outflow_map_port(ntohs(udph->source), &udp_list, &newp) == -1) {
					printk(KERN_ERR "ivi_v4v6_xmit: fail to perform ivi mapping for port %d (UDP).\n", ntohs(udph->source));
					// Just let the packet pass with original address.
				} else {
					udph->source = htons(newp);
				}
				
				break;
				
			case IPPROTO_ICMP:
				icmph = (struct icmphdr *)payload;
				
				if (icmph->type == ICMP_ECHO || icmph->type == ICMP_ECHOREPLY) {
					if (get_outflow_map_port(ntohs(icmph->un.echo.id), &icmp_list, &newp) == -1) {
						printk(KERN_ERR "ivi_v4v6_xmit: fail to perform ivi mapping for id %d (ICMP).\n", ntohs(icmph->un.echo.id));
						// Just let the packet pass with original address.
					} else {
						icmph->un.echo.id = htons(newp);
					}
				} else {
					printk(KERN_ERR "ivi_v4v6_xmit: unsupported ICMP type in ivi mapping. Drop packet now.\n");
					return 0;
				}
				
				break;
			
			default:
				printk(KERN_ERR "ivi_v4v6_xmit: unsupported protocol %d for ivi mapping operation.\n", ip4h->protocol);
		}
	}

	hlen = sizeof(struct ipv6hdr);
	plen = htons(ip4h->tot_len) - (ip4h->ihl * 4);
	if (!(newskb = alloc_skb(1600, alloc_prio))) {
		printk(KERN_ERR "ivi_v4v6_xmit: failed to allocate new socket buffer.\n");
		return 0;  // Drop packet on low memory
	}
	skb_reserve(newskb, LL_RESERVED_SPACE((skb_dst(skb))->dev));
	
	ip6h = (struct ipv6hdr *)skb_put(newskb, hlen);
	if (unlikely(ipaddr_4to6(&(ip4h->saddr), &(ip6h->saddr), addr_fmt) != 0)) {
		kfree_skb(newskb);
		return 0;
	}

	/* Do not append suffix for dst address translation */
	if (unlikely(ipaddr_4to6(&(ip4h->daddr), &(ip6h->daddr), ADDR_FMT_NONE) != 0)) {
		kfree_skb(newskb);
		return 0;
	}
	
	*(__u32 *)ip6h = __constant_htonl(0x60000000);
	ip6h->hop_limit = ip4h->ttl;
	ip6h->payload_len = htons(plen);
	ip6h->nexthdr = ip4h->protocol;  //XXX: Need to be xlated for ICMP protocol.
	
	payload = (__u8 *)skb_put(newskb, plen);
	switch (ip6h->nexthdr) {
		case IPPROTO_TCP:
			skb_copy_bits(skb, ip4h->ihl * 4, payload, plen);
			tcph = (struct tcphdr *)payload;
			tcph->check = 0;
			tcph->check = csum_ipv6_magic(&(ip6h->saddr), &(ip6h->daddr), plen, IPPROTO_TCP, csum_partial(payload, plen, 0));
			break;
		
		case IPPROTO_UDP:
			skb_copy_bits(skb, ip4h->ihl * 4, payload, plen);
			udph = (struct udphdr *)payload;
			udph->check = 0;
			udph->check = csum_ipv6_magic(&(ip6h->saddr), &(ip6h->daddr), plen, IPPROTO_UDP, csum_partial(payload, plen, 0));
			break;
		
		case IPPROTO_ICMP:  // indicating ICMPv6 packet
			skb_copy_bits(skb, ip4h->ihl * 4, payload, plen);
			icmp6h = (struct icmp6hdr *)payload;
			if (icmp6h->icmp6_type == ICMP_ECHO || icmp6h->icmp6_type == ICMP_ECHOREPLY) {
				icmp6h->icmp6_type = (icmp6h->icmp6_type == ICMP_ECHO) ? ICMPV6_ECHO_REQUEST : ICMPV6_ECHO_REPLY;
				ip6h->nexthdr = IPPROTO_ICMPV6;
				icmp6h->icmp6_cksum = 0;
				icmp6h->icmp6_cksum = csum_ipv6_magic(&(ip6h->saddr), &(ip6h->daddr), plen, IPPROTO_ICMPV6, csum_partial(payload, plen, 0));
			} else {
				printk(KERN_DEBUG "ivi_v4v6_xmit: unsupported ICMP type %d in xlate. Drop packet.\n", icmp6h->icmp6_type);
				kfree_skb(newskb);
				return 0;
			}
			break;
		
		default:
			memcpy(payload, skb->data, plen);	
	}
	
	skb_dst_set(newskb, dst_clone(skb_dst(skb)));
	skb_set_network_header(newskb, 0);
	err = ip6_route_me_harder(newskb);
	if (unlikely(err != 0)) {
		printk(KERN_DEBUG "ivi_v4v6_xmit: ip6_route_me_harder() failed with return value %d.\n", err);
		kfree_skb(newskb);
		return 0;
	}
	
	err = ip6_local_out(newskb);
	if (likely(err == 0)) {
		// Send IPv6 skb success. Free old skb and return 1.
		kfree_skb(skb);
		return 1;
	} else {
		printk(KERN_DEBUG "ivi_v4v6_xmit: ip6_local_out() failed with return value %d.\n", err);
		return 0;  // Packet will be dropped by netfilter.
	}
}
EXPORT_SYMBOL(ivi_v4v6_xmit);

int ivi_v6v4_xmit(struct sk_buff *skb) {
	struct sk_buff *newskb;
	struct ethhdr *eth6, *eth4;
	struct iphdr *ip4h;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;
	__u8 *payload;

	int hlen, plen;
	
	eth6 = eth_hdr(skb);
	if (eth6->h_proto == __constant_ntohs(ETH_P_IP)) {
		// This should not happen since we are hooked on PF_INET6.
		printk(KERN_DEBUG "ivi_v6v4_xmit: IPv4 packet received on IPv6 hook.\n");
		return -EINVAL;  // Just accept.
	}
	
	ip6h = ipv6_hdr(skb);
	if (mc_v6_addr(&(ip6h->daddr))) {
		// By pass ipv6 multicast packet (for ND)
		printk(KERN_DEBUG "ivi_v6v4_xmit: by pass ipv6 multicast packet, possibly ND packet.\n");
		return -EINVAL;
	}
	
	if (addr_is_v6host(&(ip6h->daddr)) == 0) {
		// Do not translate packets that are not heading toward the v4 network.
		printk(KERN_DEBUG "ivi_v6v4_xmit: by pass packet that is not to the v4 host, routing system will handle them.\n");
		return -EINVAL;  // Just accept.
	}
/*
	if (addr_in_v6network(&(ip6h->saddr))) {
		// Do not translate packets that are from the v6 network where the host v4 network is mapped into.
		printk(KERN_DEBUG "ivi_v6v4_xmit: by pass packet that is from the host v6 network.\n");
		return -EINVAL;  // Just accept.
	}
*/
	hlen = sizeof(struct iphdr);
	plen = ntohs(ip6h->payload_len);
	if (!(newskb = dev_alloc_skb(1600))) {
		printk(KERN_ERR "ivi_v6v4_xmit: failed to allocate new socket buffer.\n");
		return 0;  // Drop packet on low memory
	}
	skb_reserve(newskb, 2);  // Align IP header on 16 byte boundary (ETH_LEN + 2)
	
	eth4 = (struct ethhdr *)skb_put(newskb, ETH_HLEN);
	// Keep mac unchanged
	memcpy(eth4, eth6, 12);
	eth4->h_proto  = __constant_ntohs(ETH_P_IP);
	ip4h = (struct iphdr *)skb_put(newskb, hlen);
	if (unlikely(ipaddr_6to4(&(ip6h->saddr), &(ip4h->saddr)) != 0)) {
		kfree_skb(newskb);
		return 0;
	}
	
	if (unlikely(ipaddr_6to4(&(ip6h->daddr), &(ip4h->daddr)) != 0)) {
		kfree_skb(newskb);
		return 0;
	}
	
	*(__u16 *)ip4h = __constant_htons(0x4500);
	ip4h->tot_len = htons(hlen + plen);
	ip4h->id = 0;
	ip4h->frag_off = 0;
	ip4h->ttl = ip6h->hop_limit;
	ip4h->protocol = ip6h->nexthdr;  //XXX: need to be xlated for ICMPv6 protocol

	payload = (__u8 *)skb_put(newskb, plen);
	switch (ip4h->protocol) {
		case IPPROTO_TCP:
			skb_copy_bits(skb, 40, payload, plen);
			tcph = (struct tcphdr *)payload;
			
			if (addr_fmt != ADDR_FMT_NONE) {
				__be16 oldp;
				
				if (get_inflow_map_port(ntohs(tcph->dest), &tcp_list, &oldp) == -1) {
					printk(KERN_ERR "ivi_v6v4_xmit: fail to perform ivi mapping for port %d (TCP).\n", ntohs(tcph->dest));
					kfree_skb(newskb);
					return 0;
				} else {
					tcph->dest = htons(oldp);
				}
			}
			
			tcph->check = 0;
			tcph->check = csum_tcpudp_magic(ip4h->saddr, ip4h->daddr, plen, IPPROTO_TCP, csum_partial(payload, plen, 0));
			break;
		
		case IPPROTO_UDP:
			skb_copy_bits(skb, 40, payload, plen);
			udph = (struct udphdr *)payload;
			
			if (addr_fmt != ADDR_FMT_NONE) {
				__be16 oldp;
				
				if (get_inflow_map_port(ntohs(udph->dest), &udp_list, &oldp) == -1) {
					printk(KERN_ERR "ivi_v6v4_xmit: fail to perform ivi mapping for port %d (UDP).\n", ntohs(udph->dest));
					kfree_skb(newskb);
					return 0;
				} else {
					udph->dest = htons(oldp);
				}
			}
			
			udph->check = 0;
			udph->check = csum_tcpudp_magic(ip4h->saddr, ip4h->daddr, plen, IPPROTO_UDP, csum_partial(payload, plen, 0));
			break;
		
		case IPPROTO_ICMPV6:  // indicating ICMPv4 packet
			skb_copy_bits(skb, 40, payload, plen);
			icmph = (struct icmphdr *)payload;
			
			if (icmph->type == ICMPV6_ECHO_REQUEST || icmph->type == ICMPV6_ECHO_REPLY) {
				icmph->type = (icmph->type == ICMPV6_ECHO_REQUEST) ? ICMP_ECHO : ICMP_ECHOREPLY;
				ip4h->protocol = IPPROTO_ICMP;
				
				if (addr_fmt != ADDR_FMT_NONE) {
					__be16 oldp;
					
					if (get_inflow_map_port(ntohs(icmph->un.echo.id), &icmp_list, &oldp) == -1) {
						printk(KERN_ERR "ivi_v6v4_xmit: fail to perform ivi mapping for id %d (ICMP).\n", ntohs(icmph->un.echo.id));
						kfree_skb(newskb);
						return 0;
					} else {
						icmph->un.echo.id = htons(oldp);
					}
				}
				
				icmph->checksum = 0;
				icmph->checksum = ip_compute_csum(icmph, plen);
			} else {
				printk(KERN_DEBUG "ivi_v6v4_xmit: unsupported ICMPv6 type %d in xlate (possibly ND packet). By pass.\n", icmph->type);
				return -EINVAL;
			}
			
			break;
		
		default:
			memcpy(payload, skb->data + 40, plen);
	}
	ip4h->check = 0;
	ip4h->check = ip_fast_csum((__u8 *)ip4h, ip4h->ihl);
	
	// Prepare to re-enter the protocol stack
	//newskb->dev = skb->dev;  // Receive this new packet from the same device again.
	//skb_reset_mac_header(newskb);
	//newskb->protocol = __constant_htons(ETH_P_IP);
	//newskb->pkt_type = PACKET_HOST;
	newskb->protocol = eth_type_trans(newskb, skb->dev);  // eth_type_trans will set dev and many other fields for us:)
	newskb->ip_summed = CHECKSUM_NONE;
	
	netif_rx(newskb);
	return 0;
}
EXPORT_SYMBOL(ivi_v6v4_xmit);

static int __init ivi_xmit_init(void) {
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "IVI: module ivi_xmit loaded.\n");
#endif
	return 0;
}
module_init(ivi_xmit_init);

static void __exit ivi_xmit_exit(void) {
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "IVI: module ivi_xmit unloaded.\n");
#endif
}
module_exit(ivi_xmit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ZHU Yuncheng <haoyu@cernet.edu.cn>");
MODULE_AUTHOR("Wentao Shang <wentaoshang@gmail.com>");
MODULE_DESCRIPTION("IVI Packet Translation & Transmission Kernel Module");
