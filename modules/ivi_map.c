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

__be16 adjacent = 1;
EXPORT_SYMBOL(adjacent);

/* list operations */

// Get current size of the list, must be protected by spin lock when calling this function
static __inline int get_list_size(struct map_list *list)
{
	return list->size;
}

#ifdef IVI_HASH

// Init list
void init_map_list(struct map_list *list, time_t timeout)
{
	int i;
	spin_lock_init(&list->lock);
	for (i = 0; i < IVI_HTABLE_SIZE; i++) {
		INIT_HLIST_HEAD(&list->out_chain[i]);
		INIT_HLIST_HEAD(&list->in_chain[i]);
	}
	list->size = 0;
	list->last_alloc = 0;
	list->timeout = timeout;
}
EXPORT_SYMBOL(init_map_list);

// Check whether a newport is in use now, must be protected by spin lock when calling this function
static __inline int port_in_use(__be16 port, struct map_list *list)
{
	int ret = 0;
	int hash;
	struct map_tuple *iter;
	struct hlist_node *temp;

	hash = port_hashfn(port);
	if (!hlist_empty(&list->in_chain[hash])) {
		hlist_for_each_entry(iter, temp, &list->in_chain[hash], in_node) {
			if (iter->newport == port) {
				ret = 1;
				break;
			}
		}
	}

	return ret;
}

// Add a new map, the pointer to the new map_tuple is returned on success, must be protected by spin lock when calling this function
static struct map_tuple* add_new_map(__be16 oldp, __be16 newp, struct map_list *list)
{
	struct map_tuple *map;
	int hash;
	map = (struct map_tuple*)kmalloc(sizeof(struct map_tuple), GFP_ATOMIC);
	if (map == NULL) {
		printk(KERN_DEBUG "add_new_map: kmalloc failed for map_tuple.\n");
		return NULL;
	}
	
	map->oldport = oldp;
	map->newport = newp;
	do_gettimeofday(&map->timer);

	hash = port_hashfn(oldp);
	hlist_add_head(&map->out_node, &list->out_chain[hash]);
	hash = port_hashfn(newp);
	hlist_add_head(&map->in_node, &list->in_chain[hash]);
	list->size++;
	list->last_alloc = newp;
#ifdef IVI_DEBUG_MAP
	printk(KERN_DEBUG "add_new_map: add new map %d -> %d\n", oldp, newp);
#endif
	return map;
}

// Refresh the timer for each map_tuple, must NOT acquire spin lock when calling this function
void refresh_map_list(struct map_list *list)
{
	struct map_tuple *iter;
	struct hlist_node *loop;
	struct hlist_node *temp;
	struct timeval now;
	time_t delta;
	int i;
	
	do_gettimeofday(&now);
	
	spin_lock_bh(&list->lock);
	// Iterate all the map_tuple through out_chain only, in_chain contains the same info.
	for (i = 0; i < IVI_HTABLE_SIZE; i++) {
		hlist_for_each_entry_safe(iter, loop, temp, &list->out_chain[i], out_node) {
			delta = now.tv_sec - iter->timer.tv_sec;
			if (delta >= list->timeout) {
				hlist_del(&iter->out_node);
				hlist_del(&iter->in_node);
				list->size--;
#ifdef IVI_DEBUG_MAP
				printk(KERN_DEBUG "refresh_map_list: time out map %d -> %d on out_chain[%d]\n", iter->oldport, iter->newport, i);
#endif
				kfree(iter);
			}
		}
	}
	spin_unlock_bh(&list->lock);
}
EXPORT_SYMBOL(refresh_map_list);

// Clear the entire list, must NOT acquire spin lock when calling this function
void free_map_list(struct map_list *list)
{
	struct map_tuple *iter;
	struct hlist_node *loop;
	struct hlist_node *temp;
	int i;
	
	spin_lock_bh(&list->lock);
	// Iterate all the map_tuple through out_chain only, in_chain contains the same info.
	for (i = 0; i < IVI_HTABLE_SIZE; i++) {
		hlist_for_each_entry_safe(iter, loop, temp, &list->out_chain[i], out_node) {
			hlist_del(&iter->out_node);
			hlist_del(&iter->in_node);
			list->size--;
#ifdef IVI_DEBUG_MAP
			printk(KERN_DEBUG "free_map_list: delete map %d -> %d on out_chain[%d]\n", iter->oldport, iter->newport, i);
#endif
			kfree(iter);
		}
	}
	spin_unlock_bh(&list->lock);
}
EXPORT_SYMBOL(free_map_list);

/* mapping operations */

// Get mapped port for outflow packet, input and output are in host byte order, return -1 if failed
int get_outflow_map_port(__be16 oldp, struct map_list *list, __be16 *newp)
{
	__be16 retport;
	int hash;
	
	refresh_map_list(list);
	
	*newp = 0;
	
	spin_lock_bh(&list->lock);
	
	if (get_list_size(list) >= (int)(64513 / ratio)) {
		spin_unlock_bh(&list->lock);
#ifdef IVI_DEBUG_MAP
		printk(KERN_DEBUG "get_outflow_map_port: map list full.\n");
#endif
		return -1;
	}
	
	retport = 0;

	hash = port_hashfn(oldp);
	if (!hlist_empty(&list->out_chain[hash])) {
		struct map_tuple *iter;
		struct hlist_node *temp;
		hlist_for_each_entry(iter, temp, &list->out_chain[hash], out_node) {
			if (iter->oldport == oldp) {
				retport = iter->newport;
				do_gettimeofday(&iter->timer);
#ifdef IVI_DEBUG_MAP
				printk(KERN_DEBUG "get_outflow_map_port: find map %d -> %d on out_chain[%d]\n", iter->oldport, iter->newport, hash);
#endif
				break;
			}
		}
	}
	
	if (retport == 0) {
		__be16 rover_j, rover_k;

		if (ratio == 1) {
			// We are in 1:1 mapping mode, use old port directly.
			retport = oldp;
		} else {
			int remaining;
			__be16 low, high;
			
			low = (__u16)(1023 / ratio / adjacent) + 1;
			high = (__u16)(65536 / ratio / adjacent) - 1;
			remaining = (high - low) + 1;
			
			if (list->last_alloc != 0) {
				rover_j = list->last_alloc / ratio / adjacent;
				rover_k = list->last_alloc % adjacent + 1;
				if (rover_k == adjacent) {
					rover_j++;
					rover_k = 0;
				}
			} else {
				rover_j = low;
				rover_k = 0;
			}
			
			do { 
				retport = (rover_j * ratio + offset) * adjacent + rover_k;
				if (!port_in_use(retport, list))
					break;
				
				rover_k++;
				if (rover_k == adjacent) {
					rover_j++;
					remaining--;
					rover_k = 0;
					if (rover_j > high)
						rover_j = low;
				}
			} while (--remaining > 0);
			
			if (remaining <= 0) {
				spin_unlock_bh(&list->lock);
				printk(KERN_DEBUG "get_outflow_map_port: failed to assign a new map port for %d\n", oldp);
				return -1;
			}
		}
		
		if (add_new_map(oldp, retport, list) == NULL) {
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
int get_inflow_map_port(__be16 newp, struct map_list *list, __be16 *oldp)
{
	struct map_tuple *iter;
	struct hlist_node *temp;
	int ret = -1;
	int hash;
	
	refresh_map_list(list);
	
	*oldp = 0;
	
	spin_lock_bh(&list->lock);
	
	hash = port_hashfn(newp);
	if (hlist_empty(&list->in_chain[hash])) {
		spin_unlock_bh(&list->lock);
#ifdef IVI_DEBUG_MAP
		printk(KERN_DEBUG "get_inflow_map_port: in_chain[%d] empty.\n", hash);
#endif
		return -1;
	}

	hlist_for_each_entry(iter, temp, &list->in_chain[hash], in_node) {
		if (iter->newport == newp) {
			*oldp = iter->oldport;
			do_gettimeofday(&iter->timer);
#ifdef IVI_DEBUG_MAP
			printk(KERN_DEBUG "get_inflow_map_port: find map %d -> %d on in_chain[%d]\n", iter->oldport, iter->newport, hash);
#endif
			ret = 0;
			break;
		}
	}
	
	spin_unlock_bh(&list->lock);
	
	return ret;
}
EXPORT_SYMBOL(get_inflow_map_port);

#else

// Init list
void init_map_list(struct map_list *list, time_t timeout)
{
	spin_lock_init(&list->lock);
	INIT_LIST_HEAD(&list->chain);
	list->size = 0;
	list->last_alloc = 0;
	list->timeout = timeout;
}
EXPORT_SYMBOL(init_map_list);

// Check whether a port is in use now, must be protected by spin lock when calling this function
static __inline int port_in_use(__be16 port, struct map_list *list)
{
	int ret = 0;

	if (!list_empty(&list->chain)) {
		struct map_tuple *iter;
		list_for_each_entry(iter, &list->chain, node) {
			if (iter->newport == port) {
				ret = 1;
				break;
			}
		}
	}

	return ret;
}

// Add a new map, the pointer to the new map_tuple is returned on success, must be protected by spin lock when calling this function
static struct map_tuple* add_new_map(__be16 oldp, __be16 newp, struct map_list *list)
{
	struct map_tuple *map;
	map = (struct map_tuple*)kmalloc(sizeof(struct map_tuple), GFP_ATOMIC);
	if (map == NULL) {
		printk(KERN_DEBUG "add_new_map: kmalloc failed for map_tuple.\n");
		return NULL;
	}
	
	map->oldport = oldp;
	map->newport = newp;
	do_gettimeofday(&map->timer);
	
	list_add(&map->node, &list->chain);
	list->size++;
	list->last_alloc = newp;
#ifdef IVI_DEBUG_MAP
	printk(KERN_DEBUG "add_new_map: add new map %d -> %d\n", oldp, newp);
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
#ifdef IVI_DEBUG_MAP
			printk(KERN_DEBUG "refresh_map_list: time out map %d -> %d\n", iter->oldport, iter->newport);
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
#ifdef IVI_DEBUG_MAP
		printk(KERN_DEBUG "free_map_list: delete map %d -> %d\n", iter->oldport, iter->newport);
#endif
		kfree(iter);
	}
	spin_unlock_bh(&list->lock);
}
EXPORT_SYMBOL(free_map_list);

/* mapping operations */

// Get mapped port for outflow packet, input and output are in host byte order, return -1 if failed
int get_outflow_map_port(__be16 oldp, struct map_list *list, __be16 *newp)
{
	__be16 retport;
	
	refresh_map_list(list);
	
	*newp = 0;
	
	spin_lock_bh(&list->lock);
	
	if (get_list_size(list) >= (int)(64513 / ratio)) {
		spin_unlock_bh(&list->lock);
		printk(KERN_DEBUG "get_outflow_map_port: map list full.\n");
		return -1;
	}
	
	retport = 0;
	
	if (!list_empty(&list->chain)) {
		struct map_tuple *iter;
		list_for_each_entry(iter, &list->chain, node) {
			if (iter->oldport == oldp) {
				retport = iter->newport;
				do_gettimeofday(&iter->timer);
#ifdef IVI_DEBUG_MAP
				printk(KERN_DEBUG "get_outflow_map_port: find map %d -> %d\n", iter->oldport, iter->newport);
#endif
				break;
			}
		}
	}
	
	if (retport == 0) {
		__be16 rover_j, rover_k;

		if (ratio == 1) {
			// We are in 1:1 mapping mode, use old port directly.
			retport = oldp;
		} else {
			int remaining;
			__be16 low, high;
			
			low = (__u16)(1023 / ratio / adjacent) + 1;
			high = (__u16)(65536 / ratio / adjacent) - 1;
			remaining = (high - low) + 1;
			
			if (list->last_alloc != 0) {
				rover_j = list->last_alloc / ratio / adjacent;
				rover_k = list->last_alloc % adjacent + 1;
				if (rover_k == adjacent) {
					rover_j++;
					rover_k = 0;
				}
			} else {
				rover_j = low;
				rover_k = 0;
			}
			
			do { 
				retport = (rover_j * ratio + offset) * adjacent + rover_k;
				if (!port_in_use(retport, list))
					break;
				
				rover_k++;
				if (rover_k == adjacent) {
					rover_j++;
					remaining--;
					rover_k = 0;
					if (rover_j > high)
						rover_j = low;
				}
			} while (--remaining > 0);
			
			if (remaining <= 0) {
				spin_unlock_bh(&list->lock);
				printk(KERN_DEBUG "get_outflow_map_port: failed to assign a new map port for %d\n", oldp);
				return -1;
			}
		}
		
		if (add_new_map(oldp, retport, list) == NULL) {
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
int get_inflow_map_port(__be16 newp, struct map_list *list, __be16 *oldp)
{
	struct map_tuple *iter;
	int ret = -1;
	
	refresh_map_list(list);
	
	*oldp = 0;
	
	spin_lock_bh(&list->lock);
	
	if (list_empty(&list->chain)) {
		spin_unlock_bh(&list->lock);
#ifdef IVI_DEBUG_MAP
		printk(KERN_DEBUG "get_inflow_map_port: map list empty.\n");
#endif
		return -1;
	}

	list_for_each_entry(iter, &list->chain, node) {
		if (iter->newport == newp) {
			*oldp = iter->oldport;
			do_gettimeofday(&iter->timer);
#ifdef IVI_DEBUG_MAP
			printk(KERN_DEBUG "get_inflow_map_port: find map %d -> %d\n", iter->oldport, iter->newport);
#endif
			ret = 0;
			break;
		}
	}
	
	spin_unlock_bh(&list->lock);
	
	return ret;
}
EXPORT_SYMBOL(get_inflow_map_port);
#endif


static int __init ivi_map_init(void) {
#ifdef IVI_HASH
	printk(KERN_INFO "IVI: module ivi_map use hash list.\n");
#endif
	init_map_list(&udp_list, 60);
	init_map_list(&icmp_list, 30);
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "IVI: module ivi_map loaded.\n");
#endif 
	return 0;
}
module_init(ivi_map_init);

static void __exit ivi_map_exit(void) {
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
