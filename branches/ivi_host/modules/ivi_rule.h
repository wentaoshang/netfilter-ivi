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


#ifndef NIP4
#define NIP4(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]
#define NIP4_FMT "%u.%u.%u.%u"
#endif

#ifndef NIP6
#define NIP6(addr) \
	ntohs((addr).s6_addr16[0]), \
	ntohs((addr).s6_addr16[1]), \
	ntohs((addr).s6_addr16[2]), \
	ntohs((addr).s6_addr16[3]), \
	ntohs((addr).s6_addr16[4]), \
	ntohs((addr).s6_addr16[5]), \
	ntohs((addr).s6_addr16[6]), \
	ntohs((addr).s6_addr16[7])
#define NIP6_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
#endif


struct rule_info {
	u32 prefix4;
	int plen4;
	struct in6_addr prefix6;
	int plen6;
	u8 format;
};

extern int ivi_rule_lookup(u32 key, struct in6_addr *prefix6, int *plen6, u8 *fmt);
extern int ivi_rule_insert(struct rule_info *rule);
extern int ivi_rule_delete(struct rule_info *rule);
extern void ivi_rule_flush(void);

#endif /* IVI_RULE_H */
