#ifndef IVI_NF_H
#define IVI_NF_H

#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netdevice.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/route.h>

#include "ivi_config.h"
#include "ivi_map.h"
#include "ivi_xmit.h"

extern int nf_getv4dev(struct net_device *dev);
extern int nf_getv6dev(struct net_device *dev);
extern int nf_running(const int run);

extern int ivi_nf_init(void);
extern void ivi_nf_exit(void);

#endif /* IVI_NF_H */
