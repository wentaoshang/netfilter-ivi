#ifndef IVI_RULE6_H
#define IVI_RULE6_H

#include <linux/module.h>

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <net/ip.h>
#include <net/ipv6.h>

#include "ivi_config.h"
#include "ivi_rule.h"

extern int ivi_rule6_insert(struct rule_info *rule);
extern int ivi_rule6_lookup(struct in6_addr *addr, int *plen, u8 *fmt);
extern int ivi_rule6_delete(struct rule_info *rule);
extern void ivi_rule6_flush(void);

#endif
