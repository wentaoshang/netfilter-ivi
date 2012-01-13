#ifndef IVI_XMIT_H
#define IVI_XMIT_H

#ifdef __KERNEL__

#include <linux/module.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <asm/checksum.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <linux/icmp.h>
#include <net/ndisc.h>
#include <net/route.h>

#include "ivi_config.h"
#include "ivi_rule.h"
#include "ivi_rule6.h"
#include "ivi_map.h"
#include "ivi_map_tcp.h"

extern __be32 v4network;
extern __be32 v4mask;
extern __be32 v4publicaddr;
extern __u8 v6prefix[16];
extern __be32 v6prefixlen;

extern u8 ivi_mode;

extern u8 hgw_fmt;

extern u16 mss_limit;

extern int ivi_v4v6_xmit(struct sk_buff *skb);
extern int ivi_v6v4_xmit(struct sk_buff *skb);
extern int ivi_v4_dev(struct net_device *dev);
extern int ivi_v6_dev(struct net_device *dev);


#endif	/* __KERNEL__ */
#endif	/* IVI_XMIT_H */
