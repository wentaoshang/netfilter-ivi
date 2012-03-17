#ifndef IVI_RULE_H
#define IVI_RULE_H

#include <linux/module.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/inetdevice.h>

#include "ivi_config.h"

extern int ivi_rule_lookup(u32 key, struct in6_addr *prefix6, int *plen6, u16 *ratio, u16 *adjacent, u8 *fmt);
extern int ivi_rule_insert(struct rule_info *rule);
extern int ivi_rule_delete(struct rule_info *rule);
extern void ivi_rule_flush(void);

extern int ivi_rule_init(void);
extern void ivi_rule_exit(void);

#endif /* IVI_RULE_H */
