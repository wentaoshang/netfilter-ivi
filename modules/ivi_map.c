/* File name    :  ivi_map.c
 * Author       :  Wentao Shang
 *
 * Contents     :
 *	This file defines the generic mapping list data structure and basic 
 *	operations, which will be used in other modules. 'ivi_map' module 
 *	will be installed first when running './control start' command.
 *
 */

#include "ivi_map.h"

struct map_list tcp_list;
EXPORT_SYMBOL(tcp_list);

struct map_list udp_list;
EXPORT_SYMBOL(udp_list);

struct map_list icmp_list;
EXPORT_SYMBOL(icmp_list);


/* ratio and offset together indicate the port pool range */
__be16 ratio = 1;
EXPORT_SYMBOL(ratio);

__be16 offset = 0;
EXPORT_SYMBOL(offset);

__be16 suffix = 0;    // if addr fmt is ADDR_FMT_SUFFIX, this 2 bytes code is used instead
EXPORT_SYMBOL(suffix);

/* list operations */

// Get current size of the list, must be protected by spin lock when calling this function
static __inline int get_list_size(struct map_list *list)
{
	return list->size;
}

// Init list
void init_map_list(struct map_list *list, time_t timeout)
{
	spin_lock_init(&list->lock);
	INIT_LIST_HEAD(&list->chain);
	list->size = 0;
	list->timeout = timeout;
	list->last_alloc = 0;
	memset(list->used, 0, 65536 * sizeof(__u8));
}
EXPORT_SYMBOL(init_map_list);

// Check whether a port is in use now, must be protected by spin lock when calling this function
static __inline int port_in_use(unsigned int port, struct map_list *list)
{
	return (list->used[port]);
}

// Add a new map, the pointer to the new map_tuple is returned on success, must be protected by spin lock when calling this function
struct map_tuple* add_new_map(__be32 oldaddr, __be16 oldp, __be16 newp, __be16 last, struct map_list *list)
{
	struct map_tuple *map;
	map = (struct map_tuple*)kmalloc(sizeof(struct map_tuple), GFP_ATOMIC);
	if (map == NULL) {
		printk("add_new_map: kmalloc failed for map_tuple.\n");
		return NULL;
	}
	
	map->oldaddr = oldaddr;
	map->oldport = oldp;
	map->newport = newp;
	do_gettimeofday(&map->timer);
	
	list_add(&map->node, &list->chain);
	list->size++;
	list->last_alloc = last;
	list->used[newp] = 1;
#ifdef IVI_DEBUG
	printk("add_new_map: new map added: %x:%d -> %d.\n", oldaddr, oldp, newp );
#endif
	return map;
}

// Refresh the timer for each map_tuple, must NOT acquire spin lock when calling this function
void refresh_map_list(struct map_list *list)
{
	struct map_tuple *iter;
	struct map_tuple *temp;
	struct timeval now;
	time_t delta;
	do_gettimeofday(&now);
	
	spin_lock_bh(&list->lock);
	list_for_each_entry_safe(iter, temp, &list->chain, node) {
		delta = now.tv_sec - iter->timer.tv_sec;
		if (delta >= list->timeout) {
			list_del(&iter->node);
			list->size--;
			list->used[iter->newport] = 0;
#ifdef IVI_DEBUG
			printk("refresh_map_list: map %x:%d -> %d time out.\n", iter->oldaddr, iter->oldport, iter->newport);
#endif
			kfree(iter);
		}
	}
	spin_unlock_bh(&list->lock);
}
EXPORT_SYMBOL(refresh_map_list);

// Clear the entire list, must NOT acquire spin lock when calling this function
void free_map_list(struct map_list *list)
{
	struct map_tuple *iter;
	struct map_tuple *temp;
	
	spin_lock_bh(&list->lock);
	list_for_each_entry_safe(iter, temp, &list->chain, node) {
		list_del(&iter->node);
		list->size--;
#ifdef IVI_DEBUG
		printk("free_map_list: map %d -> %d deleted.\n", iter->oldport, iter->newport);
#endif
		kfree(iter);
	}
	memset(list->used, 0, 65536 * sizeof(__u8));
	spin_unlock_bh(&list->lock);
}
EXPORT_SYMBOL(free_map_list);


/* mapping operations */

// Get mapped port for outflow packet, input and output are in host byte order, return -1 if failed
int get_outflow_map_port(__be32 oldaddr, __be16 oldp, struct map_list *list, __be16 *newp)
{
	__be16 retport;
	
	refresh_map_list(list);
	
	*newp = 0;
	
	spin_lock_bh(&list->lock);
	
	if (get_list_size(list) >= (int)(64513 / ratio)) {
		spin_unlock_bh(&list->lock);
		printk("get_outflow_map_port: map list full.\n");
		return -1;
	}
	
	retport = 0;
	
	if (!list_empty(&list->chain)) {
		struct map_tuple *iter;
		list_for_each_entry(iter, &list->chain, node) {
			if (iter->oldport == oldp && iter->oldaddr == oldaddr) {
				retport = iter->newport;
				do_gettimeofday(&iter->timer);
				printk("get_outflow_map_port: find map %x:%d -> %d.\n", oldaddr, oldp, retport);
				break;
			}
		}
	}
	
	if (retport == 0) {
		int remaining;
		__be16 rover, low, high;
		
		low = (__u16)(1023 / ratio) + 1;
		high = (__u16)(65536 / ratio) - 1;
		remaining = (high - low) + 1;

		if (list->last_alloc != 0)
			rover = list->last_alloc + 1;
		else
			rover = low;
		
		do { 
			retport = rover * ratio + offset;
			if (!port_in_use(retport, list))
				break;
			
			if (++rover > high)
				rover = low;
			
		} while (--remaining > 0);
		
		if (remaining <= 0) {
			spin_unlock_bh(&list->lock);
			printk("get_outflow_map_port: failed to assign a new map port for port: %d.\n", oldp);
			return -1;
		}
		
		if (add_new_map(oldaddr, oldp, retport, rover, list) == NULL) {
			spin_unlock_bh(&list->lock);
			return -1;
		}
	}
	
	spin_unlock_bh(&list->lock);
	
	*newp = retport;
	
	return 0;
}
EXPORT_SYMBOL(get_outflow_map_port);

// Get mapped port and address for inflow packet, input and output are in host bypt order, return -1 if failed
int get_inflow_map_port(__be16 newp, struct map_list *list, __be32 *oldaddr, __be16 *oldp)
{
	struct map_tuple *iter;
	int ret = -1;
	
	refresh_map_list(list);
	
	*oldp = 0;
	*oldaddr = 0;
	
	spin_lock_bh(&list->lock);
	
	if (list_empty(&list->chain)) {
		spin_unlock_bh(&list->lock);
		printk("get_inflow_map_port: map list empty.\n");
		return -1;
	}

	list_for_each_entry(iter, &list->chain, node) {
		if (iter->newport == newp) {
			*oldaddr = iter->oldaddr;
			*oldp = iter->oldport;
			do_gettimeofday(&iter->timer);
			printk("get_inflow_map_port: find map %x:%d -> %d.\n", *oldaddr, *oldp, newp);
			ret = 0;
			break;
		}
	}
	
	spin_unlock_bh(&list->lock);
	
	return ret;
}
EXPORT_SYMBOL(get_inflow_map_port);

static int __init ivi_map_init(void) {
	init_map_list(&tcp_list, 60);
	init_map_list(&udp_list, 60);
	init_map_list(&icmp_list, 30);
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "IVI: module ivi_map loaded.\n");
#endif 
	return 0;
}
module_init(ivi_map_init);

static void __exit ivi_map_exit(void) {
	free_map_list(&tcp_list);
	free_map_list(&udp_list);
	free_map_list(&icmp_list);
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "IVI: module ivi_map unloaded.\n");
#endif
}
module_exit(ivi_map_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wentao Shang <wentaoshang@gmail.com>");
MODULE_DESCRIPTION("IVI NAT44 Address Port Mapping Kernel Module");
