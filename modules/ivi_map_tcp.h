/* File name     :  ivi_map.h
 * Author        :  Wentao Shang
 * 
 * Contents      :
 *    This file is the header file for the 'ivi_map_tcp.c' file.
 *
 */

#ifndef NFIVI_MAP_TCP_H
#define NFIVI_MAP_TCP_H

#include <linux/module.h>

#include <linux/time.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/module.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/ipv6.h>
#include <net/ip6_checksum.h>
#include <asm/unaligned.h>

#include <net/tcp.h>

#include "ivi_config.h"
#include "ivi_map.h"

#define SECS * HZ
#define MINS * 60 SECS
#define HOURS * 60 MINS
#define DAYS * 24 HOURS

// Packet flow direction
typedef enum _PACKET_DIR
{
    PACKET_DIR_LOCAL = 0,  // Sent from local to remote
    PACKET_DIR_REMOTE,     // Sent from remote to local
    PACKET_DIR_MAX
} PACKET_DIR, *PPACKET_DIR;


typedef enum _TCP_STATUS
{
    TCP_STATUS_NONE = 0,      // Initial state: 0
    TCP_STATUS_SYN_SENT,      // SYN only packet sent: 1
    TCP_STATUS_SYN_RECV,      // SYN-ACK packet sent: 2
    TCP_STATUS_ESTABLISHED,   // ACK packet sent: 3
    TCP_STATUS_FIN_WAIT,      // FIN packet sent: 4
    TCP_STATUS_CLOSE_WAIT,    // ACK sent after FIN received: 5
    TCP_STATUS_LAST_ACK,      // FIN sent after FIN received: 6
    TCP_STATUS_TIME_WAIT,     // Last ACK sent: 7
    TCP_STATUS_CLOSE,         // Connection closed: 8
    TCP_STATUS_SYN_SENT2,     // SYN only packet received after SYN sent, simultaneous open: 9
    TCP_STATUS_MAX,
    TCP_STATUS_IGNORE
} TCP_STATUS, *PTCP_STATUS;

#define STATE_OPTION_WINDOW_SCALE      0x01    // Sender uses windows scale
#define STATE_OPTION_SACK_PERM         0x02    // Sender allows SACK option
#define STATE_OPTION_CLOSE_INIT        0x04    // Sender sent Fin first
#define STATE_OPTION_DATA_UNACK        0x10    // Has unacknowledged data
#define STATE_OPTION_MAXACK_SET        0x20    // MaxAck in sender state info has been set. 
                                               // This flag is set when we see the first non-zero
                                               // ACK in TCP header sent by the sender.


typedef struct _TCP_STATE_INFO
{
    u_int32_t  End;
    u_int32_t  MaxEnd;
    u_int32_t  MaxWindow;
    u_int32_t  MaxAck;
    u_int8_t   Scale;
    u_int8_t   Options;
} TCP_STATE_INFO, *PTCP_STATE_INFO;

typedef struct _TCP_STATE_CONTEXT
{
    struct list_head  node;
    // Indexes pointing back to port hash table
    __be16            oldport;
    __be16            newport;
    
    // TCP state info
    TCP_STATE_INFO    Seen[PACKET_DIR_MAX];     // Seen[0] for local state, Seen[1] for remote state
    struct timeval    StateSetTime;    // The time when the current state is set
    unsigned int      StateTimeOut;    // Timeout value for the current state
    TCP_STATUS        Status;
    // For detecting retransmitted packets
    PACKET_DIR        LastDir;
    u_int8_t          RetransCount;
    u_int8_t          LastControlBits;
    u_int32_t         LastWindow;
    u_int32_t         LastSeq;
    u_int32_t         LastAck;
    u_int32_t         LastEnd;
} TCP_STATE_CONTEXT, *PTCP_STATE_CONTEXT;

/* map list structure */
struct tcp_map_list
{
	spinlock_t lock;
	struct list_head chain;
	int size;
	__be16 last_alloc;  // This field is meaningless for 1:1 mapping since we will use the old port directly without allocating a new one.
	__u8 used[65536];
};


typedef enum _FILTER_STATUS
{
    FILTER_ACCEPT = 0,    // Everything is good, let the packet pass
    FILTER_DROP,          // Packet is invalid, but the state is not tainted
    FILTER_DROP_CLEAN     // Both packet and state is invalid
} FILTER_STATUS, *PFILTER_STATUS;


extern struct tcp_map_list tcp_list;

extern void init_tcp_map_list(void);

extern void refresh_tcp_map_list(void);

extern void free_tcp_map_list(void);

/* mapping operations */
extern int get_outflow_tcp_map_port(__be16 oldp, struct tcphdr *th, __u32 len, __be16 *newp);
extern int get_inflow_tcp_map_port(__be16 newp, struct tcphdr *th, __u32 len, __be16 *oldp);

#endif
