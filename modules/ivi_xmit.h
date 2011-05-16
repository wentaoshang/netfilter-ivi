#ifndef IVI_XMIT
#define IVI_XMIT

#include "ivi_config.h"

#ifdef __KERNEL__

extern int ivi_v4v6_xmit(struct sk_buff *skb);
extern int ivi_v6v4_xmit(struct sk_buff *skb);
extern int ivi_v4_dev(struct net_device *dev);
extern int ivi_v6_dev(struct net_device *dev);


#endif	/* __KERNEL__ */
#endif	/* IVI_XMIT */
