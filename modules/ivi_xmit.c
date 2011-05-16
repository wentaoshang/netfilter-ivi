/*
 * ivi_xmit.c :
 *  IVI Packet Transmission Kernel Module
 * 
 * by haoyu@cernet.edu.cn 2008.10.22
 *
 * Changes:
 *	Wentao Shang	:	Remove multicast functionality and implement skbuff re-enter.
 *	Wentao Shang	:	Simplified prefix matching and address translation, v4network and v6prefix are now hard coded.
 */
#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/kthread.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/ndisc.h>
#include <net/route.h>
#include "ivi_xmit.h"
#include "ivi_map.h"

static struct net_device *v4dev, *v6dev;

static __inline int mc_v4_addr(const unsigned int *addr) {
	return ((ntohl(*addr) & 0xe0000000) == 0xe0000000);
}
	          
static __inline int mc_v6_addr(const struct in6_addr *addr) {
	return (addr->s6_addr[0] == 0xff);
}

// v4 network where v4dev is located.
static __be32  v4network = 0x01010100;  // "1.1.1.0" in host byte order
static __be32  v4mask    = 0xffffff00;  // "/24"

// v6 prefix where v4 network is mapped into.
static __u8    v6prefix[IVI_PREFIXLEN] = { 0x20, 0x01, 0x0d, 0xa8, 0xa1, 0x23, 0xb4, 0x56 };  // "2001:da8:a123:b456::/64" in network byte order

static __inline int addr_in_v4network(const unsigned int *addr) {
	return ((ntohl(*addr) & v4mask) == v4network);
}

int addr_in_v6network(const struct in6_addr *addr) {
	__be32  embed = 0;
	int i, ret = 1;
	
	for (i = 0; i < IVI_PREFIXLEN; i++) {
		if (addr->s6_addr[i] != v6prefix[i]) {
			ret = 0;
			break;
		}
	}
	
	if (ret == 0) {
		return ret;
	}
	
	embed |= ((unsigned int)addr->s6_addr[IVI_PREFIXLEN]) << 24;
	embed |= ((unsigned int)addr->s6_addr[IVI_PREFIXLEN + 1]) << 16;
	embed |= ((unsigned int)addr->s6_addr[IVI_PREFIXLEN + 2]) << 8;
	embed |= ((unsigned int)addr->s6_addr[IVI_PREFIXLEN + 3]);
	
	return ((embed & v4mask) == v4network);
}

int ipaddr_4to6(unsigned int *v4addr, struct in6_addr *v6addr) {
	unsigned int addr = htonl(*v4addr);
	
	memset(v6addr, 0, sizeof(struct in6_addr));
	memcpy(v6addr->s6_addr, v6prefix, IVI_PREFIXLEN);
	v6addr->s6_addr[IVI_PREFIXLEN] = (unsigned char)(addr >> 24);
	v6addr->s6_addr[IVI_PREFIXLEN + 1] = (unsigned char)((addr >> 16) & 0xff);
	v6addr->s6_addr[IVI_PREFIXLEN + 2] = (unsigned char)((addr >> 8) & 0xff);
	v6addr->s6_addr[IVI_PREFIXLEN + 3] = (unsigned char)(addr & 0xff);
	return 0;  // This function always succeed.
}

int ipaddr_6to4(struct in6_addr *v6addr, unsigned int *v4addr) {
	__be32 addr = 0;
	
	addr |= ((unsigned int)v6addr->s6_addr[IVI_PREFIXLEN]) << 24;
	addr |= ((unsigned int)v6addr->s6_addr[IVI_PREFIXLEN + 1]) << 16;
	addr |= ((unsigned int)v6addr->s6_addr[IVI_PREFIXLEN + 2]) << 8;
	addr |= ((unsigned int)v6addr->s6_addr[IVI_PREFIXLEN + 3]);
	*v4addr = ntohl(addr);
	return 0;  // This function always succeed.
}

int ivi_v4v6_xmit(struct sk_buff *skb) {
	struct sk_buff *newskb;
	struct ethhdr *eth4, *eth6;
	struct iphdr *ip4h;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;
	struct udphdr *udph;
	__u8 *payload;
	
	int hlen, plen;
	
	eth4 = eth_hdr(skb);
	if (eth4->h_proto == __constant_ntohs(ETH_P_IPV6)) {
		// This should not happen since we are hooked on PF_INET.
		printk(KERN_ERR "ivi_v4v6_xmit: IPv6 packet received on IPv4 hook.\n");
		return -EINVAL;  // Just accept.
	}
	
	ip4h = ip_hdr(skb);
	if (mc_v4_addr(&(ip4h->daddr))) {
		// By pass multicast packet
		printk(KERN_ERR "ivi_v4v6_xmit: by pass ipv4 multicast packet.\n");
		return -EINVAL;
	}
	
	if (addr_in_v4network(&(ip4h->daddr))) {
		// Do not translate ipv4 packets (hair pin) that are toward v4network.
		printk(KERN_ERR "ivi_v4v6_xmit: IPv4 packet from the v4 network bypassed.\n");
		return -EINVAL;  // Just accept.
	}
	
	if (addr_in_v4network(&(ip4h->saddr)) == 0) {
		// Do not translate packets that are not from v4network, return 0 to drop packet.
		printk(KERN_ERR "ivi_v4v6_xmit: drop IPv4 packet that are not from the v4 network.\n");
		return 0;
	}
	
	if (ip4h->protocol == IPPROTO_ICMP) {
		// By pass ICMP packet
		printk(KERN_ERR "ivi_v4v6_xmit: by pass ICMP packet.\n");
		return -EINVAL;
	}
	
	hlen = sizeof(struct ipv6hdr);
	plen = htons(ip4h->tot_len) - (ip4h->ihl * 4);
	if (!(newskb = dev_alloc_skb(1600))) {
		printk(KERN_ERR "ivi_v4v6_xmit: failed to allocate new socket buffer.\n");
		return -ENOMEM;
	}
	skb_reserve(newskb, 2);  // Align IP header on 16 byte boundary (ETH_LEN + 2)
	
	eth6 = (struct ethhdr *)skb_put(newskb, ETH_HLEN);
	// Keep mac unchanged
	memcpy(eth6, eth4, 12);
	eth6->h_proto  = __constant_ntohs(ETH_P_IPV6);
	
	ip6h = (struct ipv6hdr *)skb_put(newskb, hlen);
	if (ipaddr_4to6(&(ip4h->saddr), &(ip6h->saddr)) != 0) {
		kfree_skb(newskb);
		return -EINVAL;
	}
	
	if (ipaddr_4to6(&(ip4h->daddr), &(ip6h->daddr)) != 0) {
		kfree_skb(newskb);
		return -EINVAL;
	}
	
	*(__u32 *)ip6h = __constant_htonl(0x60000000);
	ip6h->hop_limit = ip4h->ttl;
	ip6h->payload_len = htons(plen);
	ip6h->nexthdr = ip4h->protocol;
	
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
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "ivi_v4v6_xmit: netif_rx returned %d.\n", netif_rx(newskb));
	return 0;
#else
	return netif_rx(newskb);
#endif
}
EXPORT_SYMBOL(ivi_v4v6_xmit);

int ivi_v6v4_xmit(struct sk_buff *skb) {
	struct sk_buff *newskb;
	struct ethhdr *eth6, *eth4;
	struct iphdr *ip4h;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;
	struct udphdr *udph;
	__u8 *payload;

	int hlen, plen;
	
	eth6 = eth_hdr(skb);
	if (eth6->h_proto == __constant_ntohs(ETH_P_IP)) {
		// This should not happen since we are hooked on PF_INET6.
		printk(KERN_ERR "ivi_v6v4_xmit: IPv4 packet received on IPv6 hook.\n");
		return -EINVAL;  // Just accept.
	}
	
	ip6h = ipv6_hdr(skb);
	if (mc_v6_addr(&(ip6h->daddr))) {
		// By pass ipv6 multicast packet (for ND)
		printk(KERN_ERR "ivi_v6v4_xmit: by pass ipv6 multicast packet, possibly ND packet.\n");
		return -EINVAL;
	}
	
	if (addr_in_v6network(&(ip6h->saddr))) {
		// This should not happen since we have accepted all packets that are not from v6dev before calling this function.
		printk(KERN_ERR "ivi_v6v4_xmit: v4dev translated packet received on IPv6 hook.\n");
		return -EINVAL;  // Just accept.
	}
	
	if (addr_in_v6network(&(ip6h->daddr)) == 0) {
		// Do not translate packets that are not heading toward the v4 network.
		printk(KERN_ERR "ivi_v6v4_xmit: by pass packet that are not to the v4 network, routing system will handle them.\n");
		return -EINVAL;
	}
	
	if (ip6h->nexthdr == IPPROTO_ICMPV6) {
		// By pass ICMPv6 packet
		printk(KERN_ERR "ivi_v6v4_xmit: by pass ICMPv6 packet.\n");
		return -EINVAL;
	}
	
	hlen = sizeof(struct iphdr);
	plen = ntohs(ip6h->payload_len);
	if (!(newskb = dev_alloc_skb(1600))) {
		printk(KERN_ERR "ivi_v6v4_xmit: failed to allocate new socket buffer.\n");
		return -ENOMEM;
	}
	skb_reserve(newskb, 2);  // Align IP header on 16 byte boundary (ETH_LEN + 2)
	
	eth4 = (struct ethhdr *)skb_put(newskb, ETH_HLEN);
	// Keep mac unchanged
	memcpy(eth4, eth6, 12);
	eth4->h_proto  = __constant_ntohs(ETH_P_IP);
	ip4h = (struct iphdr *)skb_put(newskb, hlen);
	if (ipaddr_6to4(&(ip6h->saddr), &(ip4h->saddr)) != 0) {
		kfree_skb(newskb);
		return -EINVAL;
	}
	
	if (ipaddr_6to4(&(ip6h->daddr), &(ip4h->daddr)) != 0) {
		kfree_skb(newskb);
		return -EINVAL;
	}
	
	*(__u16 *)ip4h = __constant_htons(0x4500);
	ip4h->tot_len = htons(hlen + plen);
	ip4h->id = 0;
	ip4h->frag_off = 0;
	ip4h->ttl = ip6h->hop_limit;
	ip4h->protocol = ip6h->nexthdr;

	payload = (__u8 *)skb_put(newskb, plen);
	switch (ip4h->protocol) {
		case IPPROTO_TCP:
			skb_copy_bits(skb, 40, payload, plen);
			tcph = (struct tcphdr *)payload;
			tcph->check = 0;
			tcph->check = csum_tcpudp_magic(ip4h->saddr, ip4h->daddr, plen, IPPROTO_TCP, csum_partial(payload, plen, 0));
			break;

		case IPPROTO_UDP:
			skb_copy_bits(skb, 40, payload, plen);
			udph = (struct udphdr *)payload;
			udph->check = 0;
			udph->check = csum_tcpudp_magic(ip4h->saddr, ip4h->daddr, plen, IPPROTO_UDP, csum_partial(payload, plen, 0));
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
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "ivi_v4v6_xmit: netif_rx returned %d.\n", netif_rx(newskb));
	return 0;
#else
	return netif_rx(newskb);
#endif
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
MODULE_DESCRIPTION("IVI Packet Transmission Kernel Module");
