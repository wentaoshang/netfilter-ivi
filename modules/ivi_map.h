#ifndef IVI_MAP_H
#define IVI_MAP_H

#include <linux/in6.h>
#include "ivi_config.h"

// public structure definitions

struct rt_4to6_entry {
	unsigned int	v4prefix;
	unsigned short	v4len;
	unsigned char	v6prefix[IVI_PREFIXLEN];
};

#ifdef __KERNEL__

// global function prototypes

extern int add_4to6_entry(struct rt_4to6_entry *entry);
extern int del_4to6_entry(struct rt_4to6_entry *entry);
extern int count_4to6(void);
extern int list_4to6(struct rt_4to6_entry *rt, const int maxcount);

extern int add_6to4_entry(struct in6_addr *entry);
extern int del_6to4_entry(struct in6_addr *entry);
extern int count_6to4(void);
extern int list_6to4(struct in6_addr *rt, const int maxcount);

extern int umap_4to6(unsigned int *v4addr, struct in6_addr *v6addr);
extern int umap_6to4(struct in6_addr *v6addr, unsigned int *v4addr);

#endif /* __KERNEL__ */

#endif /* IVI_MAP_H */
