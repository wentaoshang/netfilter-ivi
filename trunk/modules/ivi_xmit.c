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
 *	Wentao Shang	:	Add rule lookup to address translation routine.
 *	Wentao Shang	:	Add core translation mode support.
 */

#include "ivi_xmit.h"


static inline int link_local_addr(const struct in6_addr *addr) {
	return ((addr->s6_addr32[0] & htonl(0xffc00000)) == htonl(0xfe800000));
}

static inline int mc_v6_addr(const struct in6_addr *addr) {
	return (addr->s6_addr[0] == 0xff);
}

static inline int addr_in_v4network(const __be32 *addr) {
	return ((ntohl(*addr) & v4mask) == v4network);
}

u8 ivi_mode = 0;  // working mode for IVI translation

/*
 * Local parameter cache for fast path local address translation in hgw mode
 */

// private v4 network where v4dev is located.
__be32 v4network = 0x01010100;  // "1.1.1.0" in host byte order

__be32 v4mask = 0xffffff00;  // "/24"

// NAT public address for v4 network
__be32 v4publicaddr = 0x03030303;  // "3.3.3.3" in host byte order

// v6 prefix where v4 network or public address is mapped into.
__u8 v6prefix[16] = { 0x20, 0x01, 0x0d, 0xa8, 0x01, 0x23, 0x04, 0x56 };  // "2001:da8:123:456::" in network byte order

__be32 v6prefixlen = 8;  // "/64" prefix length in bytes (8)

u8 hgw_fmt = 0;  // ivi translated address format


u16 mss_limit = 1440;  // max mss supported


#define ADDR_DIR_SRC 0
#define ADDR_DIR_DST 1

static int ipaddr_4to6(unsigned int *v4addr, u16 port, struct in6_addr *v6addr, u8 _dir) {
	int prefixlen;
	u32 addr;
	u16 ratio, adjacent, offset, suffix;
	u8 fmt;

	addr = ntohl(*v4addr);
	ratio = adjacent = offset = suffix = fmt = 0;

	memset(v6addr, 0, sizeof(struct in6_addr));

	if ((ivi_mode >= IVI_MODE_HGW) && (_dir == ADDR_DIR_SRC)) {
		// Fast path for local address translation in hgw mode, use global parameters
		prefixlen = v6prefixlen;
		fmt = hgw_fmt;
		memcpy(v6addr, v6prefix, prefixlen);
		ratio = hgw_ratio;
		offset = hgw_offset;
		suffix = hgw_suffix;
	} else {
		if (ivi_rule_lookup(addr, v6addr, &prefixlen, &ratio, &adjacent, &fmt) != 0) {
#ifdef IVI_DEBUG_RULE
			printk(KERN_DEBUG "ipaddr_4to6: failed to map v4 addr " NIP4_FMT "\n", NIP4(addr));
#endif
			return -1;
		}
		prefixlen = prefixlen >> 3; /* counted in bytes */
		if (fmt != ADDR_FMT_NONE && ratio && adjacent) {
			offset = (port / adjacent) % ratio;
			suffix = fls(ratio) - 1;
			suffix = suffix << 12;
			suffix += offset & 0x0fff;
		}
	}

	v6addr->s6_addr[prefixlen] = (unsigned char)(addr >> 24);
	v6addr->s6_addr[prefixlen + 1] = (unsigned char)((addr >> 16) & 0xff);
	v6addr->s6_addr[prefixlen + 2] = (unsigned char)((addr >> 8) & 0xff);
	v6addr->s6_addr[prefixlen + 3] = (unsigned char)(addr & 0xff);

	if (fmt == ADDR_FMT_POSTFIX) {
		v6addr->s6_addr16[6] = htons(ratio);
		v6addr->s6_addr16[7] = htons(offset);
	} else if (fmt == ADDR_FMT_SUFFIX) {
		v6addr->s6_addr[prefixlen + 4] = (suffix >> 8) & 0xff;
		v6addr->s6_addr[prefixlen + 5] = suffix & 0xff;
	}

	return 0;
}

static int ipaddr_6to4(struct in6_addr *v6addr, unsigned int *v4addr, u16 *ratio, u16 *adjacent, u16 *offset, u8 _dir) {
	u32 addr;
	int prefixlen;
	u8 fmt;

	addr = 0;
	fmt = 0;

	if (link_local_addr(v6addr)) {
		// Do not translate ipv6 link local address.
#ifdef IVI_DEBUG_RULE
		printk(KERN_DEBUG "ipaddr_6to4: ignore link local address.\n");
#endif
		return -1;
	}

	if ((ivi_mode >= IVI_MODE_HGW) && (_dir == ADDR_DIR_DST)) {
		// Fast path for local address translation in hgw mode
		prefixlen = v6prefixlen;
	} else {
		if (ivi_rule6_lookup(v6addr, &prefixlen, ratio, adjacent, &fmt) != 0) {
#ifdef IVI_DEBUG_RULE
			printk(KERN_DEBUG "ipaddr_6to4: failed to map v6 addr " NIP6_FMT "\n", NIP6(*v6addr));
#endif
			return -1;
		}
		prefixlen = prefixlen >> 3; /* counted in bytes */
	}

	addr |= ((unsigned int)v6addr->s6_addr[prefixlen]) << 24;
	addr |= ((unsigned int)v6addr->s6_addr[prefixlen + 1]) << 16;
	addr |= ((unsigned int)v6addr->s6_addr[prefixlen + 2]) << 8;
	addr |= ((unsigned int)v6addr->s6_addr[prefixlen + 3]);
	*v4addr = htonl(addr);

	if ((ivi_mode == IVI_MODE_CORE) && (ratio != NULL) && (offset != NULL)) {
		/* offset is obtained from ipv6 address */
		if (fmt == ADDR_FMT_POSTFIX) {
			*offset = ntohs(v6addr->s6_addr16[7]);
		} else if (fmt == ADDR_FMT_SUFFIX) {
			*offset = ((v6addr->s6_addr[prefixlen + 4] << 8) + v6addr->s6_addr[prefixlen + 5]) & 0x0fff;
		} else {
			// No port multiplex
			*offset = 0;
		}
	}

	return 0;
}

int ivi_v4v6_xmit(struct sk_buff *skb) {
	struct sk_buff *newskb;
	struct ethhdr *eth4, *eth6;
	struct iphdr *ip4h;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;
	struct icmp6hdr *icmp6h;
	__u8 *payload;
	unsigned int hlen, plen;
	u16 newp, s_port, d_port;

	eth4 = eth_hdr(skb);
	if (unlikely(eth4->h_proto != __constant_ntohs(ETH_P_IP))) {
		// This should not happen since we are hooked on PF_INET.
#ifdef IVI_DEBUG
		printk(KERN_ERR "ivi_v4v6_xmit: non-IPv4 packet type %x received on IPv4 hook.\n", ntohs(eth4->h_proto));
#endif
		return NF_ACCEPT;  // Just accept.
	}

	ip4h = ip_hdr(skb);
	if (ipv4_is_multicast(ip4h->daddr) || ipv4_is_lbcast(ip4h->daddr) || ipv4_is_loopback(ip4h->daddr)) {
		// By pass multicast packet
		//printk(KERN_DEBUG "ivi_v4v6_xmit: by pass ipv4 multicast/broadcast/loopback dest address.\n");
		return NF_ACCEPT;  // Just accept.
	}

	if (ivi_mode >= IVI_MODE_HGW && addr_in_v4network(&(ip4h->daddr))) {
		// Do not translate ipv4 packets (hair pin) that are toward v4network.
#ifdef IVI_DEBUG
		printk(KERN_DEBUG "ivi_v4v6_xmit: IPv4 packet toward the v4 network bypassed in HGW mode.\n");
#endif
		return NF_ACCEPT;  // Just accept.
	}

	if (ip4h->ttl <= 1) {
		// By pass the packet if its TTL reaches 1, the kernel routing system will
		// drop the packet and send ICMPv4 error message to the source of the packet.
		// Translating it will cause kernel to send ICMPv6 error message on v4dev
		// interface, which will never be received.
		//printk(KERN_DEBUG "ivi_v4v6_xmit: by pass ipv4 packet with TTL = 1.\n");
		return NF_ACCEPT;  // Just accept.
	}

	plen = htons(ip4h->tot_len) - (ip4h->ihl * 4);
	payload = (__u8 *)(ip4h) + (ip4h->ihl << 2);
	s_port = d_port = newp = 0;

	switch (ip4h->protocol) {
		case IPPROTO_TCP:
			tcph = (struct tcphdr *)payload;

			if (ivi_mode >= IVI_MODE_HGW) {
				if (get_outflow_tcp_map_port(ntohl(ip4h->saddr), ntohs(tcph->source), hgw_ratio, hgw_adjacent, hgw_offset, tcph, plen, &newp) == -1) {
					printk(KERN_ERR "ivi_v4v6_xmit: fail to perform port mapping for " NIPQUAD_FMT ":%d (TCP).\n", NIPQUAD(ip4h->saddr), ntohs(tcph->source));
					// Just let the packet pass with original address.
				} else {
					if (ivi_mode == IVI_MODE_HGW_NAT44) {
						// SNAT-PT
						ip4h->saddr = htonl(v4publicaddr);
					}
					tcph->source = htons(newp);
				}
			}
			s_port = ntohs(tcph->source);
			d_port = ntohs(tcph->dest);

			break;

		case IPPROTO_UDP:
			udph = (struct udphdr *)payload;

			if (ivi_mode >= IVI_MODE_HGW) {
				if (get_outflow_map_port(&udp_list, ntohl(ip4h->saddr), ntohs(udph->source), hgw_ratio, hgw_adjacent, hgw_offset, &newp) == -1) {
					printk(KERN_ERR "ivi_v4v6_xmit: fail to perform port mapping for " NIPQUAD_FMT ":%d (UDP).\n", NIPQUAD(ip4h->saddr), ntohs(udph->source));
					// Just let the packet pass with original address.
				} else {
					if (ivi_mode == IVI_MODE_HGW_NAT44) {
						// SNAT-PT
						ip4h->saddr = htonl(v4publicaddr);
					}
					udph->source = htons(newp);
				}
			}
			s_port = ntohs(udph->source);
			d_port = ntohs(udph->dest);

			break;

		case IPPROTO_ICMP:
			icmph = (struct icmphdr *)payload;

			if (icmph->type == ICMP_ECHO || icmph->type == ICMP_ECHOREPLY) {
				if (ivi_mode >= IVI_MODE_HGW) {
					if (get_outflow_map_port(&icmp_list, ntohl(ip4h->saddr), ntohs(icmph->un.echo.id), hgw_ratio, hgw_adjacent, hgw_offset, &newp) == -1) {
						printk(KERN_ERR "ivi_v4v6_xmit: fail to perform id mapping for " NIPQUAD_FMT ":%d (ICMP).\n", NIPQUAD(ip4h->saddr), ntohs(icmph->un.echo.id));
						// Just let the packet pass with original address.
					} else {
						if (ivi_mode == IVI_MODE_HGW_NAT44) {
							// SNAT-PT
							ip4h->saddr = htonl(v4publicaddr);
						}
						icmph->un.echo.id = htons(newp);
					}
				}
				s_port = d_port = ntohs(icmph->un.echo.id);
			} else {
				printk(KERN_ERR "ivi_v4v6_xmit: unsupported ICMP type %d in port mapping. Drop packet.\n", icmph->type);
				return NF_DROP;
			}

			break;

		default:
			printk(KERN_ERR "ivi_v4v6_xmit: unsupported protocol %d in port mapping.\n", ip4h->protocol);
			// Just let the packet pass with original address and port.
	}

	hlen = sizeof(struct ipv6hdr);
	if (!(newskb = dev_alloc_skb(2 + ETH_HLEN + hlen + plen))) {
		printk(KERN_ERR "ivi_v4v6_xmit: failed to allocate new socket buffer.\n");
		return NF_DROP;  // Drop packet on low memory
	}
	skb_reserve(newskb, 2);  // Align IP header on 16 byte boundary (ETH_LEN + 2)

	eth6 = (struct ethhdr *)skb_put(newskb, ETH_HLEN);
	// Keep mac unchanged
	memcpy(eth6, eth4, 12);
	eth6->h_proto  = __constant_ntohs(ETH_P_IPV6);

	ip6h = (struct ipv6hdr *)skb_put(newskb, hlen);
	if (ipaddr_4to6(&(ip4h->saddr), s_port, &(ip6h->saddr), ADDR_DIR_SRC) != 0) {
		kfree_skb(newskb);
		return NF_ACCEPT;  // Just accept.
	}

	if (ipaddr_4to6(&(ip4h->daddr), d_port, &(ip6h->daddr), ADDR_DIR_DST) != 0) {
		kfree_skb(newskb);
		return NF_ACCEPT;  // Just accept.
	}

	*(__u32 *)ip6h = __constant_htonl(0x60000000);
	ip6h->hop_limit = ip4h->ttl;
	ip6h->payload_len = htons(plen);
	ip6h->nexthdr = ip4h->protocol;  /* Need to be xlated for ICMP protocol */

	payload = (__u8 *)skb_put(newskb, plen);
	switch (ip6h->nexthdr) {
		case IPPROTO_TCP:
			skb_copy_bits(skb, ip4h->ihl * 4, payload, plen);
			tcph = (struct tcphdr *)payload;

			if (tcph->syn && (tcph->doff > 5)) {
				__u16 *option = (__u16*)tcph;
				if (option[10] == htons(0x0204)) {
					if (ntohs(option[11]) > mss_limit) {
						option[11] = htons(mss_limit);
					}
				}
			}

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
			}
			break;

		default:
			memcpy(payload, skb->data, plen);	
	}

	// Prepare to re-enter the protocol stack
	//newskb->dev = skb->dev;  // Receive this new packet from the same device again.
	//skb_reset_mac_header(newskb);
	//newskb->protocol = __constant_htons(ETH_P_IPV6);
	//newskb->pkt_type = PACKET_HOST;
	newskb->protocol = eth_type_trans(newskb, skb->dev);  // eth_type_trans will set dev and many other fields for us:)
	newskb->ip_summed = CHECKSUM_NONE;

	netif_rx(newskb);
	return NF_DROP;
}


static inline bool port_in_range(u16 _port, u16 _ratio, u16 _adjacent, u16 _offset)
{
	if (_ratio == 1)
		return true;
	else 
		return (((_port / _adjacent) % _ratio) == _offset);
}

int ivi_v6v4_xmit(struct sk_buff *skb) {
	struct sk_buff *newskb;
	struct ethhdr *eth6, *eth4;
	struct iphdr *ip4h;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;
	__u8 *payload;
	unsigned int hlen, plen;
	u16 s_ratio, s_adj, s_offset, d_ratio, d_adj, d_offset;  // Used in core mode

	eth6 = eth_hdr(skb);
	if (unlikely(eth6->h_proto != __constant_ntohs(ETH_P_IPV6))) {
		// This should not happen since we are hooked on PF_INET6.
#ifdef IVI_DEBUG
		printk(KERN_ERR "ivi_v6v4_xmit: non-IPv6 packet type %x received on IPv6 hook.\n", ntohs(eth6->h_proto));
#endif
		return NF_ACCEPT;  // Just accept.
	}

	ip6h = ipv6_hdr(skb);
	if (mc_v6_addr(&(ip6h->daddr))) {
		// By pass ipv6 multicast packet (for ND)
		//printk(KERN_DEBUG "ivi_v6v4_xmit: by pass ipv6 multicast packet, possibly ND packet.\n");
		return NF_ACCEPT;
	}

	if (ip6h->hop_limit <= 1) {
		// By pass the packet if its hop limit reaches 1, the kernel routing system will
		// drop the packet and send ICMPv6 error message to the source of the packet.
		// Translating it will cause kernel to send ICMPv4 error message on v6dev 
		// interface, which will never be received.
		//printk(KERN_DEBUG "ivi_v6v4_xmit: by pass ipv6 packet with hop limit = 1.\n");
		return NF_ACCEPT;  // Just accept.
	}

	hlen = sizeof(struct iphdr);
	plen = ntohs(ip6h->payload_len);
	if (!(newskb = dev_alloc_skb(2 + ETH_HLEN + hlen + plen))) {
		printk(KERN_ERR "ivi_v6v4_xmit: failed to allocate new socket buffer.\n");
		return NF_DROP;  // Drop packet on low memory
	}
	skb_reserve(newskb, 2);  // Align IP header on 16 byte boundary (ETH_LEN + 2)

	eth4 = (struct ethhdr *)skb_put(newskb, ETH_HLEN);
	// Keep mac unchanged
	memcpy(eth4, eth6, 12);
	eth4->h_proto  = __constant_ntohs(ETH_P_IP);
	ip4h = (struct iphdr *)skb_put(newskb, hlen);
	if (ipaddr_6to4(&(ip6h->saddr), &(ip4h->saddr), &s_ratio, &s_adj, &s_offset, ADDR_DIR_SRC) != 0) {
		goto free_accept;
	}

	if (ipaddr_6to4(&(ip6h->daddr), &(ip4h->daddr), &d_ratio, &d_adj, &d_offset, ADDR_DIR_DST) != 0) {
		goto free_accept;
	}

	*(__u16 *)ip4h = __constant_htons(0x4500);
	ip4h->tot_len = htons(hlen + plen);
	ip4h->id = 0;
	ip4h->frag_off = 0;
	ip4h->ttl = ip6h->hop_limit;
	ip4h->protocol = ip6h->nexthdr;  /* Need to be xlated for ICMPv6 protocol */

	payload = (__u8 *)skb_put(newskb, plen);
	switch (ip4h->protocol) {
		case IPPROTO_TCP:
			skb_copy_bits(skb, 40, payload, plen);
			tcph = (struct tcphdr *)payload;

			if (ivi_mode >= IVI_MODE_HGW) {
				__be32 oldaddr;
				__be16 oldp;
				
				if (get_inflow_tcp_map_port(ntohs(tcph->dest), tcph, plen, &oldaddr, &oldp) == -1) {
#ifdef IVI_DEBUG_MAP
					printk(KERN_ERR "ivi_v6v4_xmit: fail to perform port mapping for %d (TCP).\n", ntohs(tcph->dest));
#endif
					goto free_drop;
				} else {
					// DNAT-PT
					ip4h->daddr = htonl(oldaddr);
					tcph->dest = htons(oldp);
				}
			} else if (ivi_mode == IVI_MODE_CORE) {
				if (!port_in_range(ntohs(tcph->source), s_ratio, s_adj, s_offset)) {
#ifdef IVI_DEBUG
					printk(KERN_INFO "ivi_v6v4_xmit: TCP src port %d is not in range  (r=%d, m=%d, o=%d). Drop packet.\n", 
						ntohs(tcph->source), s_ratio, s_adj, s_offset);
#endif
					goto free_drop;
				}
				
				if (!port_in_range(ntohs(tcph->dest), d_ratio, d_adj, d_offset)) {
#ifdef IVI_DEBUG
					printk(KERN_INFO "ivi_v6v4_xmit: TCP dst port %d is not in range  (r=%d, m=%d, o=%d). Drop packet.\n", 
						ntohs(tcph->dest), d_ratio, d_adj, d_offset);
#endif
					goto free_drop;
				}
			}

			if (tcph->syn && (tcph->doff > 5)) {
				__u16 *option = (__u16*)tcph;
				if (option[10] == htons(0x0204)) {
					if (ntohs(option[11]) > mss_limit) {
						option[11] = htons(mss_limit);
					}
				}
			}

			tcph->check = 0;
			tcph->check = csum_tcpudp_magic(ip4h->saddr, ip4h->daddr, plen, IPPROTO_TCP, csum_partial(payload, plen, 0));
			break;

		case IPPROTO_UDP:
			skb_copy_bits(skb, 40, payload, plen);
			udph = (struct udphdr *)payload;

			if (ivi_mode >= IVI_MODE_HGW) {
				__be32 oldaddr;
				__be16 oldp;

				if (get_inflow_map_port(&udp_list,  ntohs(udph->dest), &oldaddr, &oldp) == -1) {
#ifdef IVI_DEBUG_MAP
					printk(KERN_ERR "ivi_v6v4_xmit: fail to perform port mapping for %d (UDP).\n", ntohs(udph->dest));
#endif
					goto free_drop;
				} else {
					// DNAT-PT
					ip4h->daddr = htonl(oldaddr);
					udph->dest = htons(oldp);
				}
			} else if (ivi_mode == IVI_MODE_CORE) {
				if (!port_in_range(ntohs(udph->source), s_ratio, s_adj, s_offset)) {
#ifdef IVI_DEBUG
					printk(KERN_INFO "ivi_v6v4_xmit: UDP src port %d is not in range (r=%d, m=%d, o=%d). Drop packet.\n", 
						ntohs(udph->source), s_ratio, s_adj, s_offset);
#endif
					goto free_drop;
				}
				
				if (!port_in_range(ntohs(udph->dest), d_ratio, d_adj, d_offset)) {
#ifdef IVI_DEBUG
					printk(KERN_INFO "ivi_v6v4_xmit: UDP dst port %d is not in range (r=%d, m=%d, o=%d). Drop packet.\n", 
						ntohs(udph->dest), d_ratio, d_adj, d_offset);
#endif
					goto free_drop;
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

				if (ivi_mode >= IVI_MODE_HGW) {
					__be32 oldaddr;
					__be16 oldp;

					if (get_inflow_map_port(&icmp_list, ntohs(icmph->un.echo.id), &oldaddr, &oldp) == -1) {
#ifdef IVI_DEBUG_MAP
						printk(KERN_ERR "ivi_v6v4_xmit: fail to perform id mapping for %d (ICMP).\n", ntohs(icmph->un.echo.id));
#endif
						goto free_drop;
					} else {
						// DNAT-PT
						ip4h->daddr = htonl(oldaddr);
						icmph->un.echo.id = htons(oldp);
					}
				}  else if (ivi_mode == IVI_MODE_CORE) {
					if (!port_in_range(ntohs(icmph->un.echo.id), s_ratio, s_adj, s_offset)) {
#ifdef IVI_DEBUG
						printk(KERN_INFO "ivi_v6v4_xmit: ICMP id %d is not in src range (r=%d, m=%d, o=%d). Drop packet.\n", 
							ntohs(icmph->un.echo.id), s_ratio, s_adj, s_offset);
#endif
						goto free_drop;
					}
				}

				icmph->checksum = 0;
				icmph->checksum = ip_compute_csum(icmph, plen);
			} else {
				printk(KERN_ERR "ivi_v6v4_xmit: by pass unsupported ICMPv6 type %d in xlate.\n", icmph->type);
				goto free_accept;
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
	return NF_DROP;
free_accept:
	kfree_skb(newskb);
	return NF_ACCEPT;
free_drop:
	kfree_skb(newskb);
	return NF_DROP;
}
