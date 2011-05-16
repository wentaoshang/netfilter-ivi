#ifndef IVI_XMIT
#define IVI_XMIT

#ifdef __KERNEL__

#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/kthread.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <asm/checksum.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <linux/icmp.h>
#include <net/ndisc.h>
#include <net/route.h>
#include "ivi_config.h"
#include "ivi_map.h"

extern int ivi_v4v6_xmit(struct sk_buff *skb);
extern int ivi_v6v4_xmit(struct sk_buff *skb);
extern int ivi_v4_dev(struct net_device *dev);
extern int ivi_v6_dev(struct net_device *dev);


#endif	/* __KERNEL__ */
#endif	/* IVI_XMIT */
