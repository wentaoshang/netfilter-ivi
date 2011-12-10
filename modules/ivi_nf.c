/*
 * ivi_nf.c :
 *  IVI Netfilter Address Translation Kernel Module
 *
 * by haoyu@cernet.edu.cn 2008.10.19
 *
 * Changes:
 *	Wentao Shang	:	Upgrade to 2.6.35 kernel and remove multicast translation functionality.
 */

#include "ivi_nf.h"

//
// Walk around the bug in netfilter.ipv4.h and netfilter_ipv6.h.
// Those macros are not defined when we have __KERNEL__ defined.
//
#define NF_IP_PRE_ROUTING     0
#define NF_IP6_PRE_ROUTING    0

static struct net_device *v4_dev, *v6_dev;

static int running;

unsigned int nf_hook4(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *)) {

	if ((!running) || (in != v4_dev)) {
		return NF_ACCEPT;
	}

	if (ivi_v4v6_xmit(skb) == 0) {
		return NF_DROP;
	}
	else {
		return NF_ACCEPT;
	}
}

unsigned int nf_hook6(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *)) {
	
	if ((!running) || (in != v6_dev)) {
		return NF_ACCEPT;
	}

	if (ivi_v6v4_xmit(skb) == 0) {
		return NF_DROP;
	}
	else {
		return NF_ACCEPT;
	}
}

struct nf_hook_ops v4_ops = {
	list	:	{ NULL, NULL },
	hook	:	nf_hook4,
	owner	:	THIS_MODULE,
	pf	:	PF_INET,
	hooknum	:	NF_IP_PRE_ROUTING,
	priority:	NF_IP_PRI_FIRST,
};

struct nf_hook_ops v6_ops = {
	list	:	{ NULL, NULL },
	hook	:	nf_hook6,
	owner	:	THIS_MODULE,
	pf	:	PF_INET6,
	hooknum	:	NF_IP6_PRE_ROUTING,
	priority:	NF_IP6_PRI_FIRST,
};

int nf_running(const int run) {
	running = run;
#ifdef IVI_DEBUG
	printk(KERN_ERR "set running state to %d.\n", running);
#endif
	return running;
}
EXPORT_SYMBOL(nf_running);

int nf_getv4dev(struct net_device *dev) {
	v4_dev = dev;
	ivi_v4_dev(dev);
	return 0;
}
EXPORT_SYMBOL(nf_getv4dev);

int nf_getv6dev(struct net_device *dev) {
	v6_dev = dev;
	ivi_v6_dev(dev);
	return 0;
}
EXPORT_SYMBOL(nf_getv6dev);

static int __init ivi_nf_init(void) {
	running = 0;
	v4_dev = NULL;
	v6_dev = NULL;

	nf_register_hook(&v4_ops);
	nf_register_hook(&v6_ops);

#ifdef IVI_DEBUG
	printk(KERN_ERR "IVI: module ivi_nf loaded.\n");
#endif
	return 0;
}
module_init(ivi_nf_init);

static void __exit ivi_nf_exit(void) {
	running = 0;
	v4_dev = NULL;
	v6_dev = NULL;

	nf_unregister_hook(&v4_ops);
	nf_unregister_hook(&v6_ops);

#ifdef IVI_DEBUG
	printk(KERN_ERR "IVI: module ivi_nf unloaded.\n");
#endif
}
module_exit(ivi_nf_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ZHU Yuncheng <haoyu@cernet.edu.cn>");
MODULE_AUTHOR("Wentao Shang <wentaoshang@gmail.com>");
MODULE_DESCRIPTION("IVI Netfilter Address Kernel Module");
