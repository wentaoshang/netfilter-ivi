/* File name     :  ivi_map.h
 * Author        :  Wentao Shang
 * 
 * Contents      :
 *    This file is the header file for the 'ivi_map.c' file,
 *    which contains all the system header files and definitions
 *    used in the 'ivi_map.c' file.
 *
 */

#ifndef IVI_MAP_H
#define IVI_MAP_H

#include <linux/module.h>
#include <linux/time.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "ivi_config.h"

/* map entry structure */
struct map_tuple {
#ifdef IVI_HASH
	struct hlist_node out_node;  // Inserted to out_chain
	struct hlist_node in_node;   // Inserted to in_chain
#else
	struct list_head node;
#endif
	__be32 oldaddr;
	__be16 oldport;
	__be16 newport;
	struct timeval timer;
};

/* map list structure */
struct map_list {
	spinlock_t lock;
#ifdef IVI_HASH
	struct hlist_head out_chain[IVI_HTABLE_SIZE];  // Map table from oldport to newport
	struct hlist_head in_chain[IVI_HTABLE_SIZE];   // Map table from newport to oldport
#else
	struct list_head chain;
#endif
	int size;
	__be16 last_alloc;  // Save the last allocate port number
	time_t timeout;
};

/* global map list variables */
extern u16 hgw_ratio;
extern u16 hgw_offset;
extern u16 hgw_suffix;
extern u16 hgw_adjacent;

extern struct map_list udp_list;
extern struct map_list icmp_list;

/* list operations */
extern void refresh_map_list(struct map_list *list);
extern void free_map_list(struct map_list *list);

/* mapping operations */
extern int get_outflow_map_port(struct map_list *list, __be32 oldaddr, __be16 oldp, u16 ratio, u16 adjacent, u16 offset, __be16 *newp);
extern int get_inflow_map_port(struct map_list *list, __be16 newp, __be32 *oldaddr, __be16 *oldp);

extern int ivi_map_init(void);
extern void ivi_map_exit(void);

#endif /* IVI_MAP_H */
