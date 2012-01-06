/*
 * ivi_nf.c :
 *  IVI Netfilter Address Translation Kernel Module
 *
 * by haoyu@cernet.edu.cn 2008.10.19
 *
 * Changes:
 *	Wentao Shang	:	Upgrade to 2.6.35 kernel and remove multicast translation functionality.
 *	Wentao Shang	:	Modified to host-based IVI.
 */

#include "ivi_nf.h"

static int running;

unsigned int nf_hook4(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *)) {
	int ret = -1;

	if (!running) {
		return NF_ACCEPT;
	}

	ret = ivi_v4v6_xmit(skb);
	
	if (ret == 0) {
		return NF_DROP;    // Tell netfilter to drop packet.
	} else if (ret == 1) {
		return NF_STOLEN;  // IVI translation success. The 'skb' is freed in v4v6 xmit function.
	} else {
		return NF_ACCEPT;  // By-pass.
	}

}

unsigned int nf_hook6_out(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *)) {
	if (!running) {
		return NF_ACCEPT;
	}
	
	if (ivi_v6v6_xmit(skb) == 0) {
		return NF_DROP;  // Tell netfilter to drop packet.
	} else {
		return NF_ACCEPT;  // Port/id map success, let netfilter continue with the packet.
	}

}

unsigned int nf_hook6(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *)) {
	if (!running) {
		return NF_ACCEPT;
	}

	if (ivi_v6v4_xmit(skb) == 0) {
		return NF_DROP;
	} else {
		return NF_ACCEPT;
	}

}

struct nf_hook_ops v4_ops = {
	list	:	{ NULL, NULL },
	hook	:	nf_hook4,
	owner	:	THIS_MODULE,
	pf	:	PF_INET,
	hooknum	:	NF_INET_LOCAL_OUT,
	priority:	NF_IP_PRI_FIRST,
};

struct nf_hook_ops v6_out_ops = {
	list	:	{ NULL, NULL },
	hook	:	nf_hook6_out,
	owner	:	THIS_MODULE,
	pf	:	PF_INET6,
	hooknum	:	NF_INET_LOCAL_OUT,
	priority:	NF_IP6_PRI_FIRST,
};

struct nf_hook_ops v6_ops = {
	list	:	{ NULL, NULL },
	hook	:	nf_hook6,
	owner	:	THIS_MODULE,
	pf	:	PF_INET6,
	hooknum	:	NF_INET_PRE_ROUTING,
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

static int __init ivi_nf_init(void) {
	running = 0;

	nf_register_hook(&v4_ops);
	nf_register_hook(&v6_out_ops);
	nf_register_hook(&v6_ops);

#ifdef IVI_DEBUG
	printk(KERN_ERR "IVI: module ivi_nf loaded.\n");
#endif
	return 0;
}
module_init(ivi_nf_init);

static void __exit ivi_nf_exit(void) {
	running = 0;

	nf_unregister_hook(&v4_ops);
	nf_unregister_hook(&v6_out_ops);
	nf_unregister_hook(&v6_ops);

#ifdef IVI_DEBUG
	printk(KERN_ERR "IVI: module ivi_nf unloaded.\n");
#endif
}
module_exit(ivi_nf_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ZHU Yuncheng <haoyu@cernet.edu.cn>");
MODULE_AUTHOR("Wentao Shang <wentaoshang@gmail.com>");
MODULE_DESCRIPTION("IVI Netfilter Hooks Kernel Module");
