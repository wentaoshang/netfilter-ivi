#ifndef IVI_NF_H
#define IVI_NF_H

#include "ivi_config.h"

#ifdef __KERNEL__

extern int nf_getv4dev(struct net_device *dev);
extern int nf_getv6dev(struct net_device *dev);
extern int nf_running(const int run);

#endif /* __KERNEL__ */
#endif /* IVI_NF_H */
