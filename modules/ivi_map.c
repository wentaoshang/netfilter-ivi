/*
 * ivi_map.c :
 *  IVI Address Mapping Kernel Module
 *
 * by haoyu@cernet.edu.cn 2008.10.09
 *
 * Changes:
 *	Wentao Shang	:	Remove multicast functionality.
 */
#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif
#include <linux/module.h>
#include <linux/slab.h>
#include "ivi_map.h"

static struct rtree_4to6 {
	struct rt_4to6_entry *rt;
	struct rtree_4to6 *lptr, *rptr;
} tree46;

static struct rtree_6to4 {
	struct in6_addr *rt;
	struct rtree_6to4 *ptr[256];
} tree64;

static struct rcache_4to6 {
	unsigned int v4addr;
	struct rt_4to6_entry *rt;
} rcache[131072];  // 0x20000 = 0xFFFF + 0xFFFF + 2

static int counter46, counter64;

int add_4to6_entry(struct rt_4to6_entry *entry) {
	struct rtree_4to6 *ptr, *new_ptr;
	int i;
	unsigned int mask = 0x80000000;
	
	ptr = &tree46;
	for (i = 0; i < entry->v4len; i++) {
		if ((entry->v4prefix & mask) == 0) {
			if (ptr->lptr == NULL) {
				if ((new_ptr = (struct rtree_4to6 *)kmalloc(sizeof(struct rtree_4to6), GFP_KERNEL)) == NULL) {
					printk(KERN_ERR "failed to allocate memory for routing tree node.\n");
					return -ENOMEM;
				}
				new_ptr->rt = NULL;
				new_ptr->lptr = NULL;
				new_ptr->rptr = NULL;
				ptr->lptr = new_ptr;
			}
			ptr = ptr->lptr;
		}
		else {
			if (ptr->rptr == NULL) {
				if ((new_ptr = (struct rtree_4to6 *)kmalloc(sizeof(struct rtree_4to6), GFP_KERNEL)) == NULL) {
					printk(KERN_ERR "failed to allocate memory for routing tree node.\n");
					return -ENOMEM;
				}
				new_ptr->rt = NULL;
				new_ptr->lptr = NULL;
				new_ptr->rptr = NULL;
				ptr->rptr = new_ptr;
			}
			ptr = ptr->rptr;
		}
		mask >>= 1;
	}

	if (ptr->rt != NULL) { // if entry for the same prefix is already exist
		printk(KERN_WARNING "entry for the same prefix exists, new entry is not inserted.\n");
		kfree(entry);
		return -EEXIST;
	}

	ptr->rt = entry;
	counter46++;
	for (i = 0; i < 131072; i++) {
		rcache[i].v4addr = 0;
	}
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "new 4-to-6 mapping entry successfully inserted, now we have %d entries.\n", counter46);
#endif
	return 0;
}
EXPORT_SYMBOL(add_4to6_entry);

static void del_4to6_recursive(struct rtree_4to6 *ptr) {
	if (ptr->lptr != NULL) {
		del_4to6_recursive(ptr->lptr);
	}
	if (ptr->rptr != NULL) {
		del_4to6_recursive(ptr->rptr);
	}
	if (ptr->rt != NULL) {
		kfree(ptr->rt);
	}
	kfree(ptr);
}

int del_4to6_entry(struct rt_4to6_entry *entry) {
	struct rtree_4to6 *ptr, *last_ptr;
	int i, side;
	unsigned int mask = 0x80000000;

	last_ptr = ptr = &tree46;
	side = (entry->v4prefix & mask) >> 31;
	
	for (i = 0; i < entry->v4len; i++) {
		if ((entry->v4prefix & mask) == 0) {
			if ((ptr->rt != NULL) || (ptr->rptr != NULL)) {
				last_ptr = ptr;
				side = 0;
			}
			if (ptr->lptr != NULL) {
				ptr = ptr->lptr;
			}
			else {
				printk(KERN_WARNING "cannot find entry for specified prefix, entry is not deleted.\n");
				kfree(entry);
				return -ENXIO;
			}
		}
		else {
			if ((ptr->rt != NULL) || (ptr->lptr != NULL)) {
				last_ptr = ptr;
				side = 1;
			}
			if (ptr->rptr != NULL) {
				ptr = ptr->rptr;
			}
			else {
				printk(KERN_WARNING "cannot find entry for specified prefix, entry is not deleted.\n");
				kfree(entry);
				return -ENXIO;
			}
		}
		mask >>= 1;
	}

	if (ptr->rt == NULL) {
		printk(KERN_WARNING "cannot find entry for specified prefix, entry is not deleted.\n");
		kfree(entry);
		return -ENXIO;
	}

	if ((ptr->lptr != NULL) || (ptr->rptr != NULL)) { // there is longer prefix under this branch
		kfree(ptr->rt);
		ptr->rt = NULL;
		kfree(entry);
	}
	else {
		if (side == 0) {
			del_4to6_recursive(last_ptr->lptr);
			last_ptr->lptr = NULL;
		}
		else {
			del_4to6_recursive(last_ptr->rptr);
			last_ptr->rptr = NULL;
		}
	}
	counter46--;
	for (i = 0; i < 131072; i++) {
		rcache[i].v4addr = 0;
	}
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "4-to-6 mapping entry successfully deleted, now we have %d entries.\n", counter46);
#endif
	return 0;
}
EXPORT_SYMBOL(del_4to6_entry);

int count_4to6(void) {
	return counter46;
}
EXPORT_SYMBOL(count_4to6);

int list_4to6(struct rt_4to6_entry *rt, const int maxcount) {
	struct rtree_4to6 *stack[32]; //maximum stack depth for IPv4 prefix is 32-bit
	int iterate[32];
	int i = 0, ptr = 0;
	
	memset (stack, 0, sizeof(struct rtree_4to6 *) * 32);
	stack[0] = &tree46;
	iterate[0] = 0;
	while (ptr >= 0) {
		switch (iterate[ptr]) {
			case 0:
				iterate[ptr] = 1;
				if (stack[ptr]->lptr != NULL) {
					stack[ptr + 1] = stack[ptr]->lptr;
					iterate[ptr + 1] = 0;
					ptr++;
				}
				break;
			case 1:
				iterate[ptr] = 2;
				if (stack[ptr]->rptr != NULL) {
					stack[ptr + 1] = stack[ptr]->rptr;
					iterate[ptr + 1] = 0;
					ptr++;
				}
				break;
			case 2:
				if (stack[ptr]->rt != NULL) {
					if (i >= maxcount) {
						printk(KERN_WARNING "actual mapping entry number is larger than counter.\n");
						return -ENOMEM;
					}
					memcpy(rt + i, stack[ptr]->rt, sizeof(struct rt_4to6_entry));
					i++;
				}
				ptr--;
				break;
		}
	}
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "successfully returned %d 4-to-6 mapping entries.\n", i);
#endif
	return i;
}
EXPORT_SYMBOL(list_4to6);

int add_6to4_entry(struct in6_addr *entry) {
	struct rtree_6to4 *ptr, *new_ptr;
	int i, j;
	
	ptr = &tree64;
	for (i = 0; i < IVI_PREFIXLEN; i++) {
		if (ptr->ptr[entry->s6_addr[i]] == NULL) {
				if ((new_ptr = (struct rtree_6to4 *)kmalloc(sizeof(struct rtree_6to4), GFP_KERNEL)) == NULL) {
					printk(KERN_ERR "failed to allocate memory for routing tree node.\n");
					return -ENOMEM;
				}
				new_ptr->rt = NULL;
				for (j = 0; j < 256; j++) {
					new_ptr->ptr[j] = NULL;
				}
				ptr->ptr[entry->s6_addr[i]] = new_ptr;
			}
			ptr = ptr->ptr[entry->s6_addr[i]];
	}

	if (ptr->rt != NULL) { // if entry for the same prefix is already exist
		printk(KERN_WARNING "entry for the same prefix exists, new entry is not inserted.\n");
		kfree(entry);
		return -EEXIST;
	}

	ptr->rt = entry;
	counter64++;
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "new 6-to-4 mapping entry successfully inserted, now we have %d entries.\n", counter46);
#endif
	return 0;
}
EXPORT_SYMBOL(add_6to4_entry);

static void del_6to4_recursive(struct rtree_6to4 *ptr) {
	int i;

	for (i = 0; i < 256; i++) {
		if (ptr->ptr[i] != NULL) {
			del_6to4_recursive(ptr->ptr[i]);
		}
	}

	if (ptr->rt != NULL) {
		kfree(ptr->rt);
	}

	kfree(ptr);
}

int del_6to4_entry(struct in6_addr *entry) {
	struct rtree_6to4 *ptr, *last_ptr;
	int i, side, flag;

	last_ptr = ptr = &tree64;
	side = entry->s6_addr[0];
	
	for (i = 0; i < IVI_PREFIXLEN; i++) {
		flag = 0;
		if (ptr->rt != NULL) {
			flag = 1;
		}
		if (flag == 0) {
			for (i = 0; i < 255; i++) {
				if (i != entry->s6_addr[i]) {
					if (ptr->ptr[i] != NULL) {
						last_ptr = ptr;
						side = 0;
						break;
					}
				}
			}
		}
		else {
			last_ptr = ptr;
			side = 0;
		}
		if (ptr->ptr[entry->s6_addr[i]] != NULL) {
			ptr = ptr->ptr[entry->s6_addr[i]];
		}
		else {
			printk(KERN_WARNING "cannot find entry for specified prefix, entry is not deleted.\n");
			kfree(entry);
			return -ENXIO;
		}
	}

	if (ptr->rt == NULL) {
		printk(KERN_WARNING "cannot find entry for specified prefix, entry is not deleted.\n");
		kfree(entry);
		return -ENXIO;
	}

	flag = 0;
	for (i = 0; i < 256; i++) {
		if (ptr->ptr[i] != NULL) {
			flag = 1;
			break;
		}
	}

	if (flag == 1) { // there is longer prefix under this branch
		kfree(ptr->rt);
		ptr->rt = NULL;
	}
	else {
		del_6to4_recursive(last_ptr->ptr[side]);
		last_ptr->ptr[side] = NULL;
	}
	kfree(entry);
	counter64--;
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "6-to-4 mapping entry successfully deleted, now we have %d entries.\n", counter46);
#endif
	return 0;
}
EXPORT_SYMBOL(del_6to4_entry);

int count_6to4(void) {
	return counter64;
}
EXPORT_SYMBOL(count_6to4);

int list_6to4(struct in6_addr *rt, const int maxcount) {
	struct rtree_6to4 *stack[16]; //maximum stack depth for IPv4 prefix is 16-byte
	int iterate[16];
	int i = 0, ptr = 0;
	
	memset (stack, 0, sizeof(struct rtree_6to4 *) * 16);
	stack[0] = &tree64;
	iterate[0] = 0;
	while (ptr >= 0) {
		if (iterate[ptr] < 256) {
			iterate[ptr]++;
			if (stack[ptr]->ptr[iterate[ptr] - 1] != NULL) {
				stack[ptr + 1] = stack[ptr]->ptr[iterate[ptr] - 1];
				iterate[ptr + 1] = 0;
				ptr++;
			}
		}
		else {
			if (stack[ptr]->rt != NULL) {
				if (i >= maxcount) {
					printk(KERN_WARNING "actual mapping entry number is larger than counter.\n");
					return -ENOMEM;
				}
				memcpy(rt + i, stack[ptr]->rt, sizeof(struct in6_addr));
				i++;
			}
			ptr--;
			break;
		}
	}
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "successfully returned %d 6-to-4 mapping entries.\n", i);
#endif
	return i;
}
EXPORT_SYMBOL(list_6to4);

int umap_4to6(unsigned int *v4addr, struct in6_addr *v6addr) {
	struct rtree_4to6 *ptr;
	struct rt_4to6_entry *entry;
	unsigned int mask = 0x80000000;
	unsigned int addr = htonl(*v4addr);
	unsigned int hash = (addr >> 16) + (addr & 0xffff);
	int i;

	if (rcache[hash].v4addr == addr) {
		entry = rcache[hash].rt;
	}
	else {
		ptr = &tree46;
		entry = tree46.rt;
		for (i = 0; i < 32; i++) {
			if ((addr & mask) == 0) {
				if (ptr->lptr != NULL) {
					ptr = ptr->lptr;
				}
				else {
					break;
				}
			}
			else {
				if (ptr->rptr != NULL) {
					ptr = ptr->rptr;
				}
				else {
					break;
				}
			}
			if (ptr->rt != NULL) {
				entry = ptr->rt;
			}
			mask >>= 1;
		}
		rcache[hash].v4addr = addr;
		rcache[hash].rt = entry;
	}

	if (entry == NULL) {
#ifdef IVI_DEBUG
		printk(KERN_DEBUG "no valid 4-to-6 mapping entry found for %hd.%hd.%hd.%hd.\n",
				(unsigned char)(addr >> 24), (unsigned char)((addr >> 16) & 0xff),
				(unsigned char)((addr >> 8) & 0xff), (unsigned char)(addr & 0xff));
#endif
		return -ENXIO;
	}

	memset(v6addr, 0, sizeof(struct in6_addr));
	memcpy(v6addr->s6_addr, entry->v6prefix, IVI_PREFIXLEN);
	v6addr->s6_addr[IVI_PREFIXLEN] = (unsigned char)(addr >> 24);
	v6addr->s6_addr[IVI_PREFIXLEN + 1] = (unsigned char)((addr >> 16) & 0xff);
	v6addr->s6_addr[IVI_PREFIXLEN + 2] = (unsigned char)((addr >> 8) & 0xff);
	v6addr->s6_addr[IVI_PREFIXLEN + 3] = (unsigned char)(addr & 0xff);
	return 0;
}
EXPORT_SYMBOL(umap_4to6);

int umap_6to4(struct in6_addr *v6addr, unsigned int *v4addr) {
	struct rtree_6to4 *ptr = &tree64;
	unsigned int addr = 0;
	int i;

	for (i = 0; i < IVI_PREFIXLEN; i++) {
		if (ptr->ptr[v6addr->s6_addr[i]] != NULL) {
			ptr = ptr->ptr[v6addr->s6_addr[i]];
		}
		else {
			break;
		}
	}
	
	if ((i < IVI_PREFIXLEN) || (ptr->rt == NULL)) {
#ifdef IVI_DEBUG
		printk(KERN_DEBUG "no valid 6-to-4 mapping entry found for %hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx.\n",
				ntohs(v6addr->s6_addr16[0]), ntohs(v6addr->s6_addr16[1]), ntohs(v6addr->s6_addr16[2]),
				ntohs(v6addr->s6_addr16[3]), ntohs(v6addr->s6_addr16[4]), ntohs(v6addr->s6_addr16[5]),
				ntohs(v6addr->s6_addr16[6]), ntohs(v6addr->s6_addr16[7]));
#endif
		return -ENXIO;
	}

	addr |= ((unsigned int)v6addr->s6_addr[IVI_PREFIXLEN]) << 24;
	addr |= ((unsigned int)v6addr->s6_addr[IVI_PREFIXLEN + 1]) << 16;
	addr |= ((unsigned int)v6addr->s6_addr[IVI_PREFIXLEN + 2]) << 8;
	addr |= ((unsigned int)v6addr->s6_addr[IVI_PREFIXLEN + 3]);
	*v4addr = ntohl(addr);
	return 0;
}
EXPORT_SYMBOL(umap_6to4);

static int __init ivi_map_init(void) {
	int i;
	
	counter46 = counter64 = 0;
	tree46.rt = NULL;
	tree46.lptr = tree46.rptr = NULL;
	tree64.rt = NULL;
	for (i = 0; i < 256; i++) {
		tree64.ptr[i] = NULL;
	}
	for (i = 0; i < 131072; i++) {
		rcache[i].v4addr = 0;
	}

#ifdef IVI_DEBUG
	printk(KERN_DEBUG "IVI: module ivi_map loaded.\n");
#endif 
	return 0;
}
module_init(ivi_map_init);

static void __exit ivi_map_exit(void) {
	int i;
	
	if (tree46.lptr != NULL) {
		del_4to6_recursive(tree46.lptr);
	}
	if (tree46.rptr != NULL) {
		del_4to6_recursive(tree46.rptr);
	}
	for (i = 0; i < 256; i++) {
		if (tree64.ptr[i] != NULL) {
			del_6to4_recursive(tree64.ptr[i]);
		}
	}
	counter46 = counter64 = 0;

#ifdef IVI_DEBUG
	printk(KERN_DEBUG "IVI: module ivi_map unloaded.\n");
#endif
}
module_exit(ivi_map_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ZHU Yuncheng <haoyu@cernet.edu.cn>");
MODULE_DESCRIPTION("IVI Address Mapping Kernel Module");
