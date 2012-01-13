/* File name     :  ivi_map.h
 * Author        :  Wentao Shang
 * 
 * Contents      :
 *    This file is the header file for the 'ivi_map_tcp.c' file.
 *
 */

#ifndef IVI_MAP_TCP_H
#define IVI_MAP_TCP_H

#include <linux/module.h>
#include <linux/time.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/tcp.h>
#include <asm/unaligned.h>
#include <net/tcp.h>

#include "ivi_config.h"
#include "ivi_map.h"

/* map list structure */
struct tcp_map_list {
	spinlock_t lock;
#ifdef IVI_HASH
	struct hlist_head out_chain[IVI_HTABLE_SIZE];  // Map table from oldport to newport
	struct hlist_head in_chain[IVI_HTABLE_SIZE];   // Map table from newport to oldport
#else
	struct list_head chain;
#endif
	int size;
	__be16 last_alloc;  // Save the last allocated port number
};

extern struct tcp_map_list tcp_list;

extern void init_tcp_map_list(void);

extern void refresh_tcp_map_list(void);

extern void free_tcp_map_list(void);

/* mapping operations */
extern int get_outflow_tcp_map_port(__be32 oldaddr, __be16 oldp, u16 ratio, u16 adjacent, u16 offset, struct tcphdr *th, __u32 len, __be16 *newp);
extern int get_inflow_tcp_map_port(__be16 newp, struct tcphdr *th, __u32 len, __be32 *oldaddr, __be16 *oldp);

extern int ivi_map_tcp_init(void);
extern void ivi_map_tcp_exit(void);

#endif /* IVI_MAP_TCP_H */
