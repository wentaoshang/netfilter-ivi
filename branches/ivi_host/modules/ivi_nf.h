#ifndef IVI_NF_H
#define IVI_NF_H

#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/route.h>
#include "ivi_config.h"
#include "ivi_map.h"
#include "ivi_xmit.h"

extern int nf_running(const int run);

#endif /* IVI_NF_H */
