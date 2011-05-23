/* File name     :  ivi_map.h
 * Author        :  Wentao Shang
 * 
 * Contents      :
 *    This file is the header file for the 'ivi_map.c' file,
 *    which contains all the system header files and definitions
 *    used in the 'nfivi_map.c' file.
 *
 */

#ifndef NFIVI_MAP_H
#define NFIVI_MAP_H

#include <linux/module.h>

#include <linux/time.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include "ivi_config.h"

/* map entry structure */
struct map_tuple {
	struct list_head node;
	__be32 oldaddr;
	__be16 oldport;
	__be16 newport;
	struct timeval timer;
};

/* map list structure */
struct map_list {
	spinlock_t lock;
	struct list_head chain;
	int size;
	time_t timeout;
	__be16 last_alloc;
	__u8 used[65536];
};

/* global map list variables */
extern __be16 ratio;
extern __be16 offset;
extern __be16 suffix;

extern struct map_list tcp_list;
extern struct map_list udp_list;
extern struct map_list icmp_list;

/* list operations */
extern void init_map_list(struct map_list *list, time_t timeout);
extern void refresh_map_list(struct map_list *list);
extern void free_map_list(struct map_list *list);

/* mapping operations */
extern int get_outflow_map_port(__be32 oldaddr, __be16 oldp, struct map_list *list, __be16 *newp);
extern int get_inflow_map_port(__be16 newp, struct map_list *list, __be32 *oldaddr, __be16 *oldp);

#endif

