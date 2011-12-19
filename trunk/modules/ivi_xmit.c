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

static struct net_device *v4dev, *v6dev;

static __inline int mc_v4_addr(const unsigned int *addr) {
	return ((ntohl(*addr) & 0xe0000000) == 0xe0000000);
}

static __inline int link_local_addr(const struct in6_addr *addr) {
	return ((addr->s6_addr32[0] & htonl(0xffc00000)) == htonl(0xfe800000));
}

static __inline int mc_v6_addr(const struct in6_addr *addr) {
	return (addr->s6_addr[0] == 0xff);
}

__u8 ivi_mode = 0;  // working mode for IVI translation
EXPORT_SYMBOL(ivi_mode);

/*
 * Local parameter cache for fast path local address translation in hgw mode
 */

// private v4 network where v4dev is located.
__be32 v4network = 0x01010100;  // "1.1.1.0" in host byte order
EXPORT_SYMBOL(v4network);

__be32 v4mask = 0xffffff00;  // "/24"
EXPORT_SYMBOL(v4mask);

// NAT public address for v4 network
__be32 v4publicaddr = 0x03030303;  // "3.3.3.3" in host byte order
EXPORT_SYMBOL(v4publicaddr);

// v6 prefix where v4 network or public address is mapped into.
__u8 v6prefix[16] = { 0x20, 0x01, 0x0d, 0xa8, 0x01, 0x23, 0x04, 0x56 };  // "2001:da8:123:456::" in network byte order
EXPORT_SYMBOL(v6prefix);

__be32 v6prefixlen = 8;  // "/64" prefix length in bytes (8)
EXPORT_SYMBOL(v6prefixlen);

__u8 addr_fmt = 0;  // ivi translated address format
EXPORT_SYMBOL(addr_fmt);

/*
// default v6 prefix where the ipv4 dest addr is mapped into.
__u8 v6default[16] = { 0x20, 0x01, 0x0d, 0xa8, 0x01, 0x23, 0x04, 0x56 };  // "2001:da8:123:456::" in network byte order
EXPORT_SYMBOL(v6default);

__be32 v6defaultlen = 8;  // "/64" prefix length in bytes (8)
EXPORT_SYMBOL(v6defaultlen);
*/

__u16 mss_limit = 1440;  // max mss supported
EXPORT_SYMBOL(mss_limit);


#define ADDR_DIR_SRC 0
#define ADDR_DIR_DST 1

static int ipaddr_4to6(unsigned int *v4addr, struct in6_addr *v6addr, u8 _dir) {
	int prefixlen;
	u8 fmt;
	u32 addr;

	addr = ntohl(*v4addr);

	memset(v6addr, 0, sizeof(struct in6_addr));

	if ((ivi_mode >= IVI_MODE_HGW) && (_dir == ADDR_DIR_SRC)) {
		// Fast path for local address translation in hgw mode
		prefixlen = v6prefixlen;
		fmt = addr_fmt;
		memcpy(v6addr, v6prefix, prefixlen);
	} else {
		if (ivi_rule_lookup(addr, v6addr, &prefixlen, &fmt) != 0) {
			printk(KERN_DEBUG "ipaddr_4to6: failed to map v4 addr " NIP4_FMT "\n", NIP4(addr));
			return -1;
		}
		prefixlen = prefixlen >> 3; /* counted in bytes */
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

static int ipaddr_6to4(struct in6_addr *v6addr, unsigned int *v4addr, u16 *_ratio, u16 *_offset, u8 _dir) {
	u32 addr;
	int prefixlen;
	u8 fmt;

	addr = 0;
	fmt = 0;

	if (link_local_addr(v6addr)) {
		// Do not translate ipv6 link local address.
#ifdef IVI_DEBUG
		printk(KERN_DEBUG "ipaddr_6to4: ignore link local address.\n");
#endif
		return -1;
	}

	if ((ivi_mode >= IVI_MODE_HGW) && (_dir == ADDR_DIR_SRC)) {
		// Fast path for local address translation in hgw mode
		prefixlen = v6prefixlen;
	} else {
		if (ivi_rule6_lookup(v6addr, &prefixlen, &fmt) != 0) {
			printk(KERN_DEBUG "ipaddr_6to4: failed to map v6 addr " NIP6_FMT "\n", NIP6(*v6addr));
			return -1;
		}
		prefixlen = prefixlen >> 3; /* counted in bytes */
	}

	addr |= ((unsigned int)v6addr->s6_addr[prefixlen]) << 24;
	addr |= ((unsigned int)v6addr->s6_addr[prefixlen + 1]) << 16;
	addr |= ((unsigned int)v6addr->s6_addr[prefixlen + 2]) << 8;
	addr |= ((unsigned int)v6addr->s6_addr[prefixlen + 3]);
	*v4addr = htonl(addr);

	if ((ivi_mode == IVI_MODE_CORE) && (_ratio != NULL) && (_offset != NULL)) {
		if (fmt == ADDR_FMT_POSTFIX) {
			*_ratio = ntohs(v6addr->s6_addr16[6]);
			*_offset = ntohs(v6addr->s6_addr16[7]);
		} else if (fmt == ADDR_FMT_SUFFIX) {
			*_ratio = 1 << ((v6addr->s6_addr[prefixlen + 4] >> 4) & 0xf);
			*_offset = ((v6addr->s6_addr[prefixlen + 4] << 8) + v6addr->s6_addr[prefixlen + 5]) & 0x0fff;
		} else {
			*_ratio = 1;  // No port multiplex
			*_offset = 0;
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

	eth4 = eth_hdr(skb);
	if (unlikely(eth4->h_proto == __constant_ntohs(ETH_P_IPV6))) {
		// This should not happen since we are hooked on PF_INET.
		printk(KERN_ERR "ivi_v4v6_xmit: IPv6 packet received on IPv4 hook.\n");
		return -EINVAL;  // Just accept.
	}

	ip4h = ip_hdr(skb);
	if (mc_v4_addr(&(ip4h->daddr))) {
		// By pass multicast packet
		//printk(KERN_ERR "ivi_v4v6_xmit: by pass ipv4 multicast packet.\n");
		return -EINVAL;
	}

	if (ip4h->ttl <= 1) {
		// By pass the packet if its TTL reaches 1, the kernel routing system will
		// drop the packet and send ICMPv4 error message to the source of the packet.
		// Translating it will cause kernel to send ICMPv6 error message on v4dev
		// interface, which will never be received.
		printk(KERN_ERR "ivi_v4v6_xmit: by pass ipv4 packet with TTL = 1.\n");
		return -EINVAL;  // Just accept.
	}

	plen = htons(ip4h->tot_len) - (ip4h->ihl * 4);
	payload = (__u8 *)(ip4h) + (ip4h->ihl << 2);

	if (ivi_mode >= IVI_MODE_HGW) {
		__be16 newp;

		switch (ip4h->protocol) {
			case IPPROTO_TCP:
				tcph = (struct tcphdr *)payload;

				if (get_outflow_tcp_map_port(ntohl(ip4h->saddr), ntohs(tcph->source), tcph, plen, &newp) == -1) {
					printk(KERN_ERR "ivi_v4v6_xmit: fail to perform nat44 mapping for %x:%d (TCP).\n", ntohl(ip4h->saddr), ntohs(tcph->source));
					// Just let the packet pass with original address.
				} else {
					if (ivi_mode == IVI_MODE_HGW_NAT44) {
						// SNAT-PT
						ip4h->saddr = htonl(v4publicaddr);
					}
					tcph->source = htons(newp);
				}

				break;

			case IPPROTO_UDP:
				udph = (struct udphdr *)payload;

				if (get_outflow_map_port(ntohl(ip4h->saddr), ntohs(udph->source), &udp_list, &newp) == -1) {
					printk(KERN_ERR "ivi_v4v6_xmit: fail to perform nat44 mapping for %x:%d (UDP).\n", ntohl(ip4h->saddr), ntohs(udph->source));
					// Just let the packet pass with original address.
				} else {
					if (ivi_mode == IVI_MODE_HGW_NAT44) {
						// SNAT-PT
						ip4h->saddr = htonl(v4publicaddr);
					}
					udph->source = htons(newp);
				}

				break;

			case IPPROTO_ICMP:
				icmph = (struct icmphdr *)payload;

				if (icmph->type == ICMP_ECHO || icmph->type == ICMP_ECHOREPLY) {
					if (get_outflow_map_port(ntohl(ip4h->saddr), ntohs(icmph->un.echo.id), &icmp_list, &newp) == -1) {
						printk(KERN_ERR "ivi_v4v6_xmit: fail to perform nat44 mapping for %x:%d (ICMP).\n", ntohl(ip4h->saddr), ntohs(icmph->un.echo.id));
						// Just let the packet pass with original address.
					} else {
						if (ivi_mode == IVI_MODE_HGW_NAT44) {
							// SNAT-PT
							ip4h->saddr = htonl(v4publicaddr);
						}
						icmph->un.echo.id = htons(newp);
					}
				} else {
					printk(KERN_ERR "ivi_v4v6_xmit: unsupported ICMP type in NAT44. Drop packet now.\n");
					return 0;
				}

				break;

			default:
				printk(KERN_ERR "ivi_v4v6_xmit: unsupported protocol %d for nat44 operation.\n", ip4h->protocol);
				// Just let the packet pass with original address.
		}
	}

	hlen = sizeof(struct ipv6hdr);
	if (!(newskb = dev_alloc_skb(2 + ETH_HLEN + hlen + plen))) {
		printk(KERN_ERR "ivi_v4v6_xmit: failed to allocate new socket buffer.\n");
		return 0;  // Drop packet on low memory
	}
	skb_reserve(newskb, 2);  // Align IP header on 16 byte boundary (ETH_LEN + 2)

	eth6 = (struct ethhdr *)skb_put(newskb, ETH_HLEN);
	// Keep mac unchanged
	memcpy(eth6, eth4, 12);
	eth6->h_proto  = __constant_ntohs(ETH_P_IPV6);

	ip6h = (struct ipv6hdr *)skb_put(newskb, hlen);
	if (ipaddr_4to6(&(ip4h->saddr), &(ip6h->saddr), ADDR_DIR_SRC) != 0) {
		kfree_skb(newskb);
		return 0;
	}

	if (ipaddr_4to6(&(ip4h->daddr), &(ip6h->daddr), ADDR_DIR_DST) != 0) {
		kfree_skb(newskb);
		return 0;
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

			if (tcph->syn && !tcph->ack && (tcph->doff > 5)) {
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
			} else {
				printk(KERN_ERR "ivi_v4v6_xmit: unsupported ICMP type in xlate. Drop packet.\n");
				kfree_skb(newskb);
				return 0;
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
	return 0;
}
EXPORT_SYMBOL(ivi_v4v6_xmit);


static __inline bool port_in_range(u16 _port, u16 _ratio, u16 _adjacent, u16 _offset)
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
	u16 s_ratio, s_offset, d_ratio, d_offset;  // Used in core mode

	eth6 = eth_hdr(skb);
	if (unlikely(eth6->h_proto == __constant_ntohs(ETH_P_IP))) {
		// This should not happen since we are hooked on PF_INET6.
		printk(KERN_ERR "ivi_v6v4_xmit: IPv4 packet received on IPv6 hook.\n");
		return -EINVAL;  // Just accept.
	}

	ip6h = ipv6_hdr(skb);
	if (mc_v6_addr(&(ip6h->daddr))) {
		// By pass ipv6 multicast packet (for ND)
		//printk(KERN_ERR "ivi_v6v4_xmit: by pass ipv6 multicast packet, possibly ND packet.\n");
		return -EINVAL;
	}

	if (ip6h->hop_limit <= 1) {
		// By pass the packet if its hop limit reaches 1, the kernel routing system will
		// drop the packet and send ICMPv6 error message to the source of the packet.
		// Translating it will cause kernel to send ICMPv4 error message on v6dev 
		// interface, which will never be received.
		printk(KERN_ERR "ivi_v6v4_xmit: by pass ipv6 packet with hop limit = 1.\n");
		return -EINVAL;  // Just accept.
	}

	hlen = sizeof(struct iphdr);
	plen = ntohs(ip6h->payload_len);
	if (!(newskb = dev_alloc_skb(2 + ETH_HLEN + hlen + plen))) {
		printk(KERN_ERR "ivi_v6v4_xmit: failed to allocate new socket buffer.\n");
		return 0;  // Drop packet on low memory
	}
	skb_reserve(newskb, 2);  // Align IP header on 16 byte boundary (ETH_LEN + 2)

	eth4 = (struct ethhdr *)skb_put(newskb, ETH_HLEN);
	// Keep mac unchanged
	memcpy(eth4, eth6, 12);
	eth4->h_proto  = __constant_ntohs(ETH_P_IP);
	ip4h = (struct iphdr *)skb_put(newskb, hlen);
	if (ipaddr_6to4(&(ip6h->saddr), &(ip4h->saddr), &s_ratio, &s_offset, ADDR_DIR_SRC) != 0) {
		kfree_skb(newskb);
		return -EINVAL;  // Just accept.
	}

	if (ipaddr_6to4(&(ip6h->daddr), &(ip4h->daddr), &d_ratio, &d_offset, ADDR_DIR_DST) != 0) {
		kfree_skb(newskb);
		return -EINVAL;  // Just accept.
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
					printk(KERN_ERR "ivi_v6v4_xmit: fail to perform nat44 mapping for %d (TCP).\n", ntohs(tcph->dest));
				} else {
					// DNAT-PT
					ip4h->daddr = htonl(oldaddr);
					tcph->dest = htons(oldp);
				}
			} else if (ivi_mode == IVI_MODE_CORE) {
				if (!port_in_range(ntohs(tcph->source), s_ratio, adjacent, s_offset)) {
					printk(KERN_INFO "ivi_v6v4_xmit: TCP src port is not in range. Drop packet.\n");
					kfree_skb(newskb);
					return 0;
				}
				
				if (!port_in_range(ntohs(tcph->dest), d_ratio, adjacent, d_offset)) {
					printk(KERN_INFO "ivi_v6v4_xmit: TCP dst port is not in range. Drop packet.\n");
					kfree_skb(newskb);
					return 0;
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

				if (get_inflow_map_port(ntohs(udph->dest), &udp_list, &oldaddr, &oldp) == -1) {
					printk(KERN_ERR "ivi_v6v4_xmit: fail to perform nat44 mapping for %d (UDP).\n", ntohs(udph->dest));
				} else {
					// DNAT-PT
					ip4h->daddr = htonl(oldaddr);
					udph->dest = htons(oldp);
				}
			} else if (ivi_mode == IVI_MODE_CORE) {
				if (!port_in_range(ntohs(udph->source), s_ratio, adjacent, s_offset)) {
					printk(KERN_INFO "ivi_v6v4_xmit: UDP src port is not in range. Drop packet.\n");
					kfree_skb(newskb);
					return 0;
				}
				
				if (!port_in_range(ntohs(udph->dest), d_ratio, adjacent, d_offset)) {
					printk(KERN_INFO "ivi_v6v4_xmit: UDP dst port is not in range. Drop packet.\n");
					kfree_skb(newskb);
					return 0;
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

					if (get_inflow_map_port(ntohs(icmph->un.echo.id), &icmp_list, &oldaddr, &oldp) == -1) {
						printk(KERN_ERR "ivi_v6v4_xmit: fail to perform nat44 mapping for %d (ICMP).\n", ntohs(icmph->un.echo.id));
					} else {
						// DNAT-PT
						ip4h->daddr = htonl(oldaddr);
						icmph->un.echo.id = htons(oldp);
					}
				}

				icmph->checksum = 0;
				icmph->checksum = ip_compute_csum(icmph, plen);
			} else {
				printk(KERN_ERR "ivi_v6v4_xmit: unsupported ICMPv6 type in xlate. Drop packet.\n");
				kfree_skb(newskb);
				return 0;
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

int ivi_v4_dev(struct net_device *dev) {
	v4dev = dev;
	return v4dev->ifindex;
}
EXPORT_SYMBOL(ivi_v4_dev);

int ivi_v6_dev(struct net_device *dev) {
	v6dev = dev;
	return v6dev->ifindex;
}
EXPORT_SYMBOL(ivi_v6_dev);

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
