/* File name    :  ivi_map_tcp.c
 * Author       :  Wentao Shang
 *
 * Contents     :
 *	This file defines the TCP mapping list data structure and basic 
 *	operations with TCP state tracking, which will be used in other modules.
 *
 */

#include "ivi_map_tcp.h"

#define SECS * HZ
#define MINS * 60 SECS
#define HOURS * 60 MINS
#define DAYS * 24 HOURS

// Packet flow direction
typedef enum _PACKET_DIR {
	PACKET_DIR_LOCAL = 0,  // Sent from local to remote
	PACKET_DIR_REMOTE,     // Sent from remote to local
	PACKET_DIR_MAX
} PACKET_DIR, *PPACKET_DIR;


typedef enum _TCP_STATUS {
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

typedef enum _FILTER_STATUS {
	FILTER_ACCEPT = 0,    // Everything is good, let the packet pass
	FILTER_DROP,          // Packet is invalid, but the state is not tainted
	FILTER_DROP_CLEAN     // Both packet and state is invalid
} FILTER_STATUS, *PFILTER_STATUS;

typedef struct _TCP_STATE_INFO {
	u_int32_t  End;
	u_int32_t  MaxEnd;
	u_int32_t  MaxWindow;
	u_int32_t  MaxAck;
	u_int8_t   Scale;
	u_int8_t   Options;
} TCP_STATE_INFO, *PTCP_STATE_INFO;

typedef struct _TCP_STATE_CONTEXT {
#ifdef IVI_HASH
	struct hlist_node out_node;  // Inserted to out_chain
	struct hlist_node in_node;   // Inserted to in_chain
#else
	struct list_head  node;
#endif
	// Indexes pointing back to port hash table
	__be16            oldport;
	__be16            newport;
	bool              xlated;

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

// TCP timeouts
static unsigned int tcp_timeouts[TCP_STATUS_MAX] __read_mostly = {
	0,        // TCP_STATUS_NONE
	2 MINS,   // TCP_STATUS_SYN_SENT
	60 SECS,  // TCP_STATUS_SYN_RECV
	5 DAYS,   // TCP_STATUS_ESTABLISHED
	2 MINS,   // TCP_STATUS_FIN_WAIT
	60 SECS,  // TCP_STATUS_CLOSE_WAIT
	30 SECS,  // TCP_STATUS_LAST_ACK
	2 MINS,   // TCP_STATUS_TIME_WAIT
	10 SECS,  // TCP_STATUS_CLOSE
	2 MINS    // TCP_STATUS_SYN_SENT2
};

static unsigned int TcpTimeOutMaxRetrans __read_mostly = 5 MINS;
static unsigned int TcpTimeOutUnack  __read_mostly     = 5 MINS;

static int TcpMaxRetrans __read_mostly = 3;

// Short name for TCP_STATUS
#define sNO TCP_STATUS_NONE
#define sSS TCP_STATUS_SYN_SENT
#define sSR TCP_STATUS_SYN_RECV
#define sES TCP_STATUS_ESTABLISHED
#define sFW TCP_STATUS_FIN_WAIT
#define sCW TCP_STATUS_CLOSE_WAIT
#define sLA TCP_STATUS_LAST_ACK
#define sTW TCP_STATUS_TIME_WAIT
#define sCL TCP_STATUS_CLOSE
#define sS2 TCP_STATUS_SYN_SENT2
#define sIV TCP_STATUS_MAX
#define sIG TCP_STATUS_IGNORE

/* What TCP flags are set from RST/SYN/FIN/ACK. */
enum tcp_bit_set {
	TCP_SYN_SET = 0,
	TCP_SYNACK_SET,
	TCP_FIN_SET,
	TCP_ACK_SET,
	TCP_RST_SET,
	TCP_NONE_SET,
};

/*
 * The TCP state transition table needs a few words...
 *
 * We are the man in the middle. All the packets go through us
 * but might get lost in transit to the destination.
 * It is assumed that the destinations can't receive segments
 * we haven't seen.
 *
 * The checked segment is in window, but our windows are *not*
 * equivalent with the ones of the sender/receiver. We always
 * try to guess the state of the current sender.
 *
 * The meaning of the states are:
 *
 * NONE:         initial state
 * SYN_SENT:     SYN-only packet seen
 * SYN_SENT2:    SYN-only packet seen from reply dir, simultaneous open
 * SYN_RECV:     SYN-ACK packet seen
 * ESTABLISHED:  ACK packet seen
 * FIN_WAIT:     FIN packet seen
 * CLOSE_WAIT:   ACK seen (after FIN)
 * LAST_ACK:     FIN seen (after FIN)
 * TIME_WAIT:    last ACK seen
 * CLOSE:        closed connection (RST)
 *
 * Packets marked as IGNORED (sIG):
 *    if they may be either invalid or valid
 *    and the receiver may send back a connection
 *    closing RST or a SYN/ACK.
 *
 * Packets marked as INVALID (sIV):
 *    if we regard them as truly invalid packets
 */
static const u8 tcp_state_table[PACKET_DIR_MAX][6][TCP_STATUS_MAX] = {
    {
/* LOCAL */
/*        sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*syn*/ { sSS, sSS, sIG, sIG, sIG, sIG, sIG, sSS, sSS, sS2 },
/*
 *    sNO -> sSS    Initialize a new connection
 *    sSS -> sSS    Retransmitted SYN
 *    sS2 -> sS2    Late retransmitted SYN
 *    sSR -> sIG
 *    sES -> sIG    Error: SYNs in window outside the SYN_SENT state
 *                  are errors. Receiver will reply with RST
 *                  and close the connection.
 *                  Or we are not in sync and hold a dead connection.
 *    sFW -> sIG
 *    sCW -> sIG
 *    sLA -> sIG
 *    sTW -> sSS    Reopened connection (RFC 1122).
 *    sCL -> sSS
 */
/*           sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*synack*/ { sIV, sIV, sIG, sIG, sIG, sIG, sIG, sIG, sIG, sSR },
/*
 *    sNO -> sIV    Too late and no reason to do anything
 *    sSS -> sIV    Client can't send SYN and then SYN/ACK
 *    sS2 -> sSR    SYN/ACK sent to SYN2 in simultaneous open
 *    sSR -> sIG
 *    sES -> sIG    Error: SYNs in window outside the SYN_SENT state
 *                  are errors. Receiver will reply with RST
 *                  and close the connection.
 *                  Or we are not in sync and hold a dead connection.
 *    sFW -> sIG
 *    sCW -> sIG
 *    sLA -> sIG
 *    sTW -> sIG
 *    sCL -> sIG
 */
/*        sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*fin*/ { sIV, sIV, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sIV },
/*
 *    sNO -> sIV    Too late and no reason to do anything...
 *    sSS -> sIV    Client migth not send FIN in this state:
 *                  we enforce waiting for a SYN/ACK reply first.
 *    sS2 -> sIV
 *    sSR -> sFW    Close started.
 *    sES -> sFW
 *    sFW -> sLA    FIN seen in both directions, waiting for
 *                  the last ACK.
 *                  Migth be a retransmitted FIN as well...
 *    sCW -> sLA
 *    sLA -> sLA    Retransmitted FIN. Remain in the same state.
 *    sTW -> sTW
 *    sCL -> sCL
 */
/*        sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*ack*/ { sES, sIV, sES, sES, sCW, sCW, sTW, sTW, sCL, sIV },
/*
 *    sNO -> sES    Assumed.
 *    sSS -> sIV    ACK is invalid: we haven't seen a SYN/ACK yet.
 *    sS2 -> sIV
 *    sSR -> sES    Established state is reached.
 *    sES -> sES    :-)
 *    sFW -> sCW    Normal close request answered by ACK.
 *    sCW -> sCW
 *    sLA -> sTW    Last ACK detected.
 *    sTW -> sTW    Retransmitted last ACK. Remain in the same state.
 *    sCL -> sCL
 */
/*         sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*rst*/  { sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL },
/*none*/ { sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV }
    },
    {
/* REMOTE */
/*        sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*syn*/ { sIV, sS2, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sS2 },
/*
 *    sNO -> sIV    Never reached.
 *    sSS -> sS2    Simultaneous open
 *    sS2 -> sS2    Retransmitted simultaneous SYN
 *    sSR -> sIV    Invalid SYN packets sent by the server
 *    sES -> sIV
 *    sFW -> sIV
 *    sCW -> sIV
 *    sLA -> sIV
 *    sTW -> sIV    Reopened connection, but server may not do it.
 *    sCL -> sIV
 */
/*           sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*synack*/ { sIV, sSR, sSR, sIG, sIG, sIG, sIG, sIG, sIG, sSR },
/*
 *    sSS -> sSR    Standard open.
 *    sS2 -> sSR    Simultaneous open
 *    sSR -> sSR    Retransmitted SYN/ACK.
 *    sES -> sIG    Late retransmitted SYN/ACK?
 *    sFW -> sIG    Might be SYN/ACK answering ignored SYN
 *    sCW -> sIG
 *    sLA -> sIG
 *    sTW -> sIG
 *    sCL -> sIG
 */
/*        sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*fin*/ { sIV, sIV, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sIV },
/*
 *    sSS -> sIV    Server might not send FIN in this state.
 *    sS2 -> sIV
 *    sSR -> sFW    Close started.
 *    sES -> sFW
 *    sFW -> sLA    FIN seen in both directions.
 *    sCW -> sLA
 *    sLA -> sLA    Retransmitted FIN.
 *    sTW -> sTW
 *    sCL -> sCL
 */
/*        sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*ack*/ { sIV, sIG, sSR, sES, sCW, sCW, sTW, sTW, sCL, sIG },
/*
 *    sSS -> sIG    Might be a half-open connection.
 *    sS2 -> sIG
 *    sSR -> sSR    Might answer late resent SYN.
 *    sES -> sES    :-)
 *    sFW -> sCW    Normal close request answered by ACK.
 *    sCW -> sCW
 *    sLA -> sTW    Last ACK detected.
 *    sTW -> sTW    Retransmitted last ACK.
 *    sCL -> sCL
 */
/*         sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*rst*/  { sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL },
/*none*/ { sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV }
    }
};


static unsigned int get_bits_index(const struct tcphdr *tcph)
{
	if (tcph->rst) return TCP_RST_SET;
	else if (tcph->syn) return (tcph->ack ? TCP_SYNACK_SET : TCP_SYN_SET);
	else if (tcph->fin) return TCP_FIN_SET;
	else if (tcph->ack) return TCP_ACK_SET;
	else return TCP_NONE_SET;
}


/*  TCP connection tracking based on 'Real Stateful TCP Packet Filtering
    in IP Filter' by Guido van Rooij.

    http://www.sane.nl/events/sane2000/papers.html
    http://www.darkart.com/mirrors/www.obfuscation.org/ipf/

    The boundaries and the conditions are changed according to RFC793:
    the packet must intersect the window (i.e. segments may be
    after the right or before the left edge) and thus receivers may ACK
    segments after the right edge of the window.

    MaxEnd    = max(sack + max(win,1)) seen in reply packets
    MaxWindow = max(max(win, 1)) + (sack - ack) seen in sent packets
    MaxWindow += seq + len - sender.MaxEnd
            if seq + len > sender.MaxEnd
    End       = max(seq + len) seen in sent packets

    I.   Upper bound for valid data:     seq <= sender.MaxEnd
    II.  Lower bound for valid data:     seq + len >= sender.End - receiver.MaxWindow
    III. Upper bound for valid (s)ack:   sack <= receiver.End
    IV.  Lower bound for valid (s)ack:   sack >= receiver.End - MAXACKWINDOW

    where sack is the highest right edge of sack block found in the packet
    or ack in the case of packet without SACK option.

    The upper bound limit for a valid (s)ack is not ignored -
    we doesn't have to deal with fragments.
*/

static inline __u32 segment_seq_plus_len(__u32 seq, size_t len, const struct tcphdr *tcph)
{
	/* XXX Should I use payload length field in IP/IPv6 header ?
	 * - YK */
	return (seq + len - tcph->doff * 4 + (tcph->syn ? 1 : 0) + (tcph->fin ? 1 : 0));
}

#define MAXACKWINCONST         66000
#define MAXACKWINDOW(sender) ((sender)->MaxWindow > MAXACKWINCONST ? (sender)->MaxWindow : MAXACKWINCONST)

static void tcp_options(struct tcphdr *th, PTCP_STATE_INFO StateInfo)
{
	unsigned char *ptr = (unsigned char *)(th) + sizeof(struct tcphdr);
	int optlen = (th->doff*4) - sizeof(struct tcphdr);
	
	if (optlen == 0)
		return;
	
	StateInfo->Scale = 0;
	StateInfo->Options = 0;
	
	while (optlen > 0) {
		unsigned char optcode = *ptr++;
		unsigned char optsize;
		
		switch (optcode) {
			case TCPOPT_EOL:
				// End of options
				return;
				
			case TCPOPT_NOP:
				// Zero padding
				optlen--;
				continue;
				
			default:
				optsize = *ptr++;
				
				if (optsize < 2) {
					// "silly options"
					return;
				}
				
				if (optsize > optlen) {
					break;  // don't parse partial options
				}
				
				if (optcode == TCPOPT_SACK_PERM && optsize == TCPOLEN_SACK_PERM) {
					StateInfo->Options |= STATE_OPTION_SACK_PERM;
				}
				else if (optcode == TCPOPT_WINDOW && optsize == TCPOLEN_WINDOW) {
					StateInfo->Scale = *ptr;
					
					if (StateInfo->Scale > 14) {
						// See RFC1323
						StateInfo->Scale = 14;
					}
					StateInfo->Options |= STATE_OPTION_WINDOW_SCALE;
				}
				ptr += optsize - 2;
				optlen -= optsize;
				break;
		}
	}
}


static void tcp_sack(struct tcphdr *th, __u32 *sack)
{
	unsigned char *ptr = (unsigned char *)(th) + sizeof(struct tcphdr);
	int optlen = (th->doff*4) - sizeof(struct tcphdr);

	if (optlen == 0)
		return;

	while (optlen > 0) {
		unsigned char optcode = *ptr++;
		unsigned char optsize, i;

		switch (optcode) {
			case TCPOPT_EOL:
				// End of options
				return;

			case TCPOPT_NOP:
				// Zero padding
				optlen--;
				continue;

			default:
				optsize = *ptr++;

				if (optsize < 2) {
					// "silly options"
					return;
				}
				
				if (optsize > optlen) {
					break;  // don't parse partial options
				}

				if (optcode == TCPOPT_SACK && optsize >= (TCPOLEN_SACK_BASE + TCPOLEN_SACK_PERBLOCK)
				    && (((optsize - TCPOLEN_SACK_BASE) % TCPOLEN_SACK_PERBLOCK) == 0)) 
				{
					for (i = 0; i < (optsize - TCPOLEN_SACK_BASE); i += TCPOLEN_SACK_PERBLOCK) {
						// Read the right edge of the SACK block, see RFC2018
						__u32 tmp = get_unaligned_be32((__be32 *)(ptr+i)+1);
						if (after(tmp, *sack)) {
							*sack = tmp;
						}
					}
					return;
				}
				ptr += optsize - 2;
				optlen -= optsize;
				break;
		}
	}
}


static bool tcp_in_window(struct tcphdr *th, __u32 len, PACKET_DIR dir, PTCP_STATE_CONTEXT StateContext)
{
	PTCP_STATE_INFO sender = &(StateContext->Seen[dir]);
	PTCP_STATE_INFO receiver = &(StateContext->Seen[!dir]);
	__u32 seq, ack, sack, end, win, swin;
	bool res;

	// Get the required data from header
	seq = ntohl(th->seq);
	ack = sack = ntohl(th->ack_seq);
	win = ntohs(th->window);
	end = segment_seq_plus_len(seq, len, th);

	if (receiver->Options & STATE_OPTION_SACK_PERM) {
		// Receiver allows SACK option from sender
		tcp_sack(th, &sack);
	}

	if (sender->MaxWindow == 0) {
		// Initialize sender data
		if (th->syn) {
			// SYN-ACK reply to a SYN or SYN from receiver in simultaneous open
			// We set receiver->MaxWin to 0 in CreateTcpStateContext().
			sender->End = sender->MaxEnd = end;
			sender->MaxWindow = ((win == 0) ? 1 : win);
			// Read TCP options on SYN packet.
			tcp_options(th, sender);

			/*
			 * RFC 1323:
			 * Both sides must send the Window Scale option
			 * to enable window scaling in either direction.
			 */
			if (!(sender->Options & STATE_OPTION_WINDOW_SCALE && receiver->Options & STATE_OPTION_WINDOW_SCALE)) {
				// At least one side does not support window scale.
				sender->Scale = receiver->Scale = 0;
			}
		}
	}
	else if (((StateContext->Status == TCP_STATUS_SYN_SENT && dir == PACKET_DIR_LOCAL)
		|| (StateContext->Status == TCP_STATUS_SYN_RECV && dir == PACKET_DIR_REMOTE))
		&& after(end, sender->End))
	{
		/*
		 * RFC 793: "if a TCP is reinitialized ... then it need
		 * not wait at all; it must only be sure to use sequence
		 * numbers larger than those recently used."
		 */
		sender->End = sender->MaxEnd = end;
		sender->MaxWindow = ((win == 0) ? 1 : win);
		// Read TCP options on SYN packet.
		tcp_options(th, sender);
    	}

	if (!(th->ack)) {
		// If there is no ACK, just pretend it was set and OK.
		ack = sack = receiver->End;
	} else if (((tcp_flag_word(th) & (TCP_FLAG_ACK|TCP_FLAG_RST)) == (TCP_FLAG_ACK|TCP_FLAG_RST)) && (ack == 0)) {
		// Broken TCP stacks, that set ACK in RST packets as well with zero ack value.
		ack = sack = receiver->End;
	}

	if (seq == end && (!(th->rst) 
	    || (seq == 0 && StateContext->Status == TCP_STATUS_SYN_SENT)))
	{
		/*
		 * Packets contains no data: we assume it is valid
		 * and check the ack value only.
		 * However RST segments are always validated by their
		 * SEQ number, except when seq == 0 (reset sent answering
		 * SYN.
		 */
		seq = end = sender->End;
	}
#ifdef IVI_DEBUG_TCP
	printk(KERN_DEBUG "tcp_in_window: seq = %u, ack = %u, sack = %u, win = %u, end = %u\n", seq, ack, sack, win, end);
	printk(KERN_DEBUG "tcp_in_window: sender end=%u maxend=%u maxwin=%u scale=%u\n", 
			sender->End, sender->MaxEnd, sender->MaxWindow, sender->Scale);
	printk(KERN_DEBUG "tcp_in_window: receiver end=%u maxend=%u maxwin=%u scale=%u\n", 
			receiver->End, receiver->MaxEnd, receiver->MaxWindow, receiver->Scale);
	printk(KERN_DEBUG "tcp_in_window: I=%d II=%d III=%d IV=%d\n",
			before(seq, sender->MaxEnd + 1),
			after(end, sender->End - receiver->MaxWindow - 1),
			before(sack, receiver->End + 1),
			after(sack, receiver->End - MAXACKWINDOW(sender) - 1));
#endif    
	if (before(seq, sender->MaxEnd + 1) && after(end, sender->End - receiver->MaxWindow - 1) &&
	    before(sack, receiver->End + 1) && after(sack, receiver->End - MAXACKWINDOW(sender) - 1))
	{
		/*
		 * Take into account window scaling (RFC 1323).
		 */
		if (!(th->syn))
			win <<= sender->Scale;

		/*
		 * Update sender data.
		 */
		swin = win + (sack - ack);
		if (sender->MaxWindow < swin) {
			sender->MaxWindow = swin;
		}
		if (after(end, sender->End)) {
			sender->End = end;
			sender->Options |= STATE_OPTION_DATA_UNACK;
		}
		if (th->ack) {
			if (!(sender->Options & STATE_OPTION_MAXACK_SET)) {
				sender->MaxAck = ack;
				sender->Options |= STATE_OPTION_MAXACK_SET;
			} else if (after(ack, sender->MaxAck)) {
				sender->MaxAck = ack;
			}
		}

		/*
		 * Update receiver data.
		 */
		if (receiver->MaxWindow != 0 && after(end, sender->MaxEnd)) {
			receiver->MaxWindow += end - sender->MaxEnd;
		}
		if (after(sack + win, receiver->MaxEnd - 1)) {
			receiver->MaxEnd = sack + win;
			if (win == 0) {
				receiver->MaxEnd++;
			}
		}
		if (ack == receiver->End) {
			receiver->Options &= ~STATE_OPTION_MAXACK_SET;
		}

		/*
		 * Check retransmissions.
		 */
		if (get_bits_index(th) == TCP_ACK_SET) {
			if (StateContext->LastDir == dir
				&& StateContext->LastSeq == seq
				&& StateContext->LastAck == ack
				&& StateContext->LastEnd == end
				&& StateContext->LastWindow == win)
			{
				StateContext->RetransCount++;
			} else {
				StateContext->LastDir = dir;
				StateContext->LastSeq = seq;
				StateContext->LastAck = ack;
				StateContext->LastEnd = end;
				StateContext->LastWindow = win;
				StateContext->RetransCount = 0;
			}
		}
		res = true;
	} else {
		res = false;
	}
#ifdef IVI_DEBUG_TCP
	printk(KERN_DEBUG "tcp_in_window: sender end=%u maxend=%u maxwin=%u scale=%u\n", 
			sender->End, sender->MaxEnd, sender->MaxWindow, sender->Scale);
	printk(KERN_DEBUG "tcp_in_window: receiver end=%u maxend=%u maxwin=%u scale=%u\n", 
			receiver->End, receiver->MaxEnd, receiver->MaxWindow, receiver->Scale);
#endif
	return res;
}

static FILTER_STATUS CreateTcpStateContext(struct tcphdr *th, __u32 len, PTCP_STATE_CONTEXT StateContext)
{
	PTCP_STATE_INFO sender = &(StateContext->Seen[0]);   // Sender is always local
	PTCP_STATE_INFO receiver = &(StateContext->Seen[1]); // Receiver is always remote
	unsigned int index = get_bits_index(th);
	__u32 seq = ntohl(th->seq);

	TCP_STATUS NewStatus = tcp_state_table[0][index][TCP_STATUS_NONE];  // We always start from NONE state

	if (NewStatus != TCP_STATUS_SYN_SENT) {
		// Invalid packet or we are in middle of a connection, which is not supported now
#ifdef IVI_DEBUG_MAP
		printk(KERN_DEBUG "CreateTcpStateContext: invalid new packet causing state change to %d, drop.\n", NewStatus);
#endif
		return FILTER_DROP_CLEAN;
	}

	// SYN packet from local
	sender->End = segment_seq_plus_len(seq, len, th);
	sender->MaxEnd = sender->End;
	sender->MaxWindow = ntohs(th->window);
	if (sender->MaxWindow == 0) {
		// Window probing
		sender->MaxWindow = 1;
	}
	// Read window scale and SACK permit options in SYN packet
	tcp_options(th, sender);

	receiver->Options = 0;
	receiver->End = 0;
	receiver->MaxEnd = 0;
	receiver->MaxWindow = 0;
	receiver->Scale = 0;

	StateContext->Status = TCP_STATUS_SYN_SENT;
	do_gettimeofday(&(StateContext->StateSetTime));
	StateContext->StateTimeOut = tcp_timeouts[TCP_STATUS_SYN_SENT];
	StateContext->LastDir = PACKET_DIR_LOCAL;
	StateContext->RetransCount = 0;
	StateContext->LastControlBits = (unsigned char)index;
	StateContext->LastWindow = sender->MaxWindow;
	StateContext->LastSeq = seq;
	StateContext->LastAck = 0;
	StateContext->LastEnd = sender->End;

	return FILTER_ACCEPT;
}


static FILTER_STATUS UpdateTcpStateContext(struct tcphdr *th, __u32 len, PACKET_DIR dir, PTCP_STATE_CONTEXT StateContext)
{
	PTCP_STATE_INFO sender = &(StateContext->Seen[dir]);
	PTCP_STATE_INFO receiver = &(StateContext->Seen[!dir]);
	TCP_STATUS  OldStatus = StateContext->Status;
	unsigned int index = get_bits_index(th);
	TCP_STATUS  NewStatus = tcp_state_table[dir][index][OldStatus];

	switch (NewStatus) {
		case TCP_STATUS_SYN_SENT:
			if (OldStatus < TCP_STATUS_TIME_WAIT) {
				// Retransmitted SYN
				break;
			} 
			else  // Reopened connection from TIME_WAIT or CLOSE state
			{
				/* RFC 1122: "When a connection is closed actively,
				 * it MUST linger in TIME-WAIT state for a time 2xMSL
				 * (Maximum Segment Lifetime). However, it MAY accept
				 * a new SYN from the remote TCP to reopen the connection
				 * directly from TIME-WAIT state, if..."
				 * We ignore the conditions because we are in the
				 * TIME-WAIT state anyway.
				 *
				 * Handle aborted connections: we and the server
				 * think there is an existing connection but the client
				 * aborts it and starts a new one.
				 */
				if (((sender->Options | receiver->Options) & STATE_OPTION_CLOSE_INIT)
					|| (StateContext->LastDir == dir && StateContext->LastControlBits == TCP_RST_SET))
				{
					/* Attempt to reopen a closed/aborted connection. */
					memset(StateContext, 0, sizeof(TCP_STATE_CONTEXT));
					return CreateTcpStateContext(th, len, StateContext);
				}
			}
			/* Fall through */
		case TCP_STATUS_IGNORE:
			// Ignored packets, just record them in LastXXX fields and do not update state machine.
			//XXX: We do not support connection pick-up at present.
			StateContext->LastDir = dir;
			StateContext->RetransCount = 0;   // Ignored packet is surely not a retransmitted packet.
			StateContext->LastControlBits = (unsigned char)index;
			StateContext->LastWindow = ntohs(th->window);
			StateContext->LastSeq = ntohl(th->seq);
			StateContext->LastAck = ntohl(th->ack_seq);
			StateContext->LastEnd = segment_seq_plus_len(StateContext->LastSeq, len, th);
#ifdef IVI_DEBUG_MAP
			printk(KERN_DEBUG "UpdateTcpStateContext: ignore packet on map %d -> %d, state %d\n", 
				StateContext->oldport, StateContext->newport, OldStatus);
#endif
			return FILTER_ACCEPT;

		case TCP_STATUS_MAX:
			// Invalid state, should be released.
#ifdef IVI_DEBUG_MAP
			printk(KERN_DEBUG "UpdateTcpStateContext: invalid packet on map %d -> %d, state %d, drop packet and clear state.\n", 
				StateContext->oldport, StateContext->newport, OldStatus);
#endif
			return FILTER_DROP_CLEAN;

		case TCP_STATUS_CLOSE:
			// This happens when we are already in CLOSE or received a RST.
			if (index == TCP_RST_SET && (receiver->Options & STATE_OPTION_MAXACK_SET) 
				&& before(ntohl(th->seq), receiver->MaxAck))
			{
				// Invalid RST
#ifdef IVI_DEBUG_MAP
				printk(KERN_DEBUG "UpdateTcpStateContext: invalid RST packet on map %d -> %d, state %d, drop packet.\n", 
					StateContext->oldport, StateContext->newport, OldStatus);
#endif
				return FILTER_DROP;
			}
			break;

		default:
			break;
	}

	if (tcp_in_window(th, len, dir, StateContext) == false) {
		// Segment is outside the window.
		return FILTER_DROP;
	}

	// From now on we have got in-window packets.
	StateContext->LastControlBits = (unsigned char)index;
	StateContext->LastDir = dir;
#ifdef IVI_DEBUG_TCP
	printk(KERN_DEBUG "UpdateTcpStateContext: syn=%d ack=%d fin=%d rst=%d old_state=%d new_state=%d\n",
		th->syn, th->ack, th->fin, th->rst, OldStatus, NewStatus);
#endif  
	StateContext->Status = NewStatus;
	if (OldStatus != NewStatus && NewStatus == TCP_STATUS_FIN_WAIT) {
		sender->Options |= STATE_OPTION_CLOSE_INIT;
	}

	// Update State Timer.
	if (StateContext->RetransCount >= TcpMaxRetrans && StateContext->StateTimeOut > TcpTimeOutMaxRetrans) {
		StateContext->StateTimeOut = TcpTimeOutMaxRetrans;
	} else if (((sender->Options | receiver->Options) & STATE_OPTION_DATA_UNACK) 
	      && StateContext->StateTimeOut > TcpTimeOutUnack) {
		StateContext->StateTimeOut = TcpTimeOutUnack;
	} else {
		StateContext->StateTimeOut = tcp_timeouts[NewStatus];
	}

	// Update state set time if state has changed.
	if (NewStatus != OldStatus) {
		//XXX: Should we also refresh timer for unchanged state?
		do_gettimeofday(&(StateContext->StateSetTime));
	}

	return FILTER_ACCEPT;
}

struct tcp_map_list tcp_list;
EXPORT_SYMBOL(tcp_list);

#ifdef IVI_HASH

void init_tcp_map_list(void)
{
	int i;
	spin_lock_init(&tcp_list.lock);
	for (i = 0; i < IVI_HTABLE_SIZE; i++) {
		INIT_HLIST_HEAD(&tcp_list.out_chain[i]);
		INIT_HLIST_HEAD(&tcp_list.in_chain[i]);
	}
	tcp_list.size = 0;
	tcp_list.last_alloc = 0;
}
EXPORT_SYMBOL(init_tcp_map_list);

// Refresh the timer for each map_tuple, must NOT acquire spin lock when calling this function
void refresh_tcp_map_list(void)
{
	PTCP_STATE_CONTEXT iter;
	struct hlist_node *loop;
	struct hlist_node *temp;
	struct timeval now;
	time_t delta;
	int i;
	do_gettimeofday(&now);
	
	spin_lock_bh(&tcp_list.lock);
	// Iterate all the map_tuple through out_chain only, in_chain contains the same info.
	for (i = 0; i < IVI_HTABLE_SIZE; i++) {
		hlist_for_each_entry_safe(iter, loop, temp, &tcp_list.out_chain[i], out_node) {
			delta = now.tv_sec - iter->StateSetTime.tv_sec;
			if (delta >= iter->StateTimeOut) {
				hlist_del(&iter->out_node);
				hlist_del(&iter->in_node);
				tcp_list.size--;
#ifdef IVI_DEBUG_MAP
				printk(KERN_DEBUG "refresh_tcp_map_list: time out map %d -> %d on out_chain[%d], TCP state %d, xlated = %d\n", 
						iter->oldport, iter->newport, i, iter->Status, iter->xlated);
#endif
				kfree(iter);
			}
		}
	}
	spin_unlock_bh(&tcp_list.lock);
}
EXPORT_SYMBOL(refresh_tcp_map_list);

// Clear the entire list, must NOT acquire spin lock when calling this function
void free_tcp_map_list(void)
{
	PTCP_STATE_CONTEXT iter;
	struct hlist_node *loop;
	struct hlist_node *temp;
	int i;
	
	spin_lock_bh(&tcp_list.lock);
	// Iterate all the map_tuple through out_chain only, in_chain contains the same info.
	for (i = 0; i < IVI_HTABLE_SIZE; i++) {
		hlist_for_each_entry_safe(iter, loop, temp, &tcp_list.out_chain[i], out_node) {
			hlist_del(&iter->out_node);
			hlist_del(&iter->in_node);
			tcp_list.size--;
#ifdef IVI_DEBUG_MAP
			printk(KERN_DEBUG "free_tcp_map_list: delete map %d -> %d on out_chain[%d], TCP state %d, xlated = %d\n", 
				iter->oldport, iter->newport, i, iter->Status, iter->xlated);
#endif
			kfree(iter);
		}
	}
	spin_unlock_bh(&tcp_list.lock);
}
EXPORT_SYMBOL(free_tcp_map_list);

// Check whether a port is in use now, must be protected by spin lock when calling this function
static __inline int tcp_port_in_use(__be16 port)
{
	int ret = 0;
	int hash;
	PTCP_STATE_CONTEXT iter;
	struct hlist_node *temp;

	hash = port_hashfn(port);
	if (!hlist_empty(&tcp_list.in_chain[hash])) {
		hlist_for_each_entry(iter, temp, &tcp_list.in_chain[hash], in_node) {
			if (iter->newport == port) {
				ret = 1;
				break;
			}
		}
	}

	return ret;
}

int get_outflow_tcp_map_port(__be16 oldp, u16 ratio, u16 adjacent, u16 offset, struct tcphdr *th, __u32 len, bool xlated, __be16 *newp)
{
	__be16 retport = 0;
	int hash;
	
	PTCP_STATE_CONTEXT StateContext = NULL;
	FILTER_STATUS ftState;

	refresh_tcp_map_list();

	if (!newp)
		return -1;
	
	*newp = 0;
	
	spin_lock_bh(&tcp_list.lock);
    
	if (tcp_list.size >= (int)(64513 / ratio)) {
		spin_unlock_bh(&tcp_list.lock);
#ifdef IVI_DEBUG_MAP
		printk(KERN_INFO "get_outflow_tcp map_port: map list full.\n");
#endif
		return -1;
	}

	hash = port_hashfn(oldp);
	if (!hlist_empty(&tcp_list.out_chain[hash])) {
		FILTER_STATUS       ftState;
        	PTCP_STATE_CONTEXT  StateContext;
        	struct hlist_node *loop;
        	struct hlist_node *temp;
		hlist_for_each_entry_safe(StateContext, loop, temp, &tcp_list.out_chain[hash], out_node) {
			if (StateContext->oldport == oldp) {
				// Update state context.
				ftState = UpdateTcpStateContext(th, len, PACKET_DIR_LOCAL, StateContext);
				
                		if (ftState == FILTER_ACCEPT) {
					retport = StateContext->newport;
#ifdef IVI_DEBUG_MAP
					printk(KERN_DEBUG "get_outflow_tcp_map_port: Found map %d -> %d on out_chain[%d], TCP state %d, xlated = %d\n", 
						StateContext->oldport, StateContext->newport, hash, StateContext->Status, StateContext->xlated);
#endif
				}
				else if (ftState == FILTER_DROP) {
					// Return -1 to drop current segment, keep the state info.
#ifdef IVI_DEBUG_MAP
					printk(KERN_DEBUG "get_outflow_tcp_map_port: Invalid packet on map %d -> %d on out_chain[%d], TCP state %d, xlated = %d\n", 
						StateContext->oldport, StateContext->newport, hash, StateContext->Status, StateContext->xlated);
#endif
				}
				else  // FILTER_DROP_CLEAN
				{
#ifdef IVI_DEBUG_MAP
					printk(KERN_DEBUG "get_outflow_tcp_map_port: Invalid state on map %d -> %d on out_chain[%d], TCP state %d, xlated = %d\n", 
						StateContext->oldport, StateContext->newport, hash, StateContext->Status, StateContext->xlated);
#endif
					// Remove state info, return -1
					hlist_del(&StateContext->out_node);
                    			hlist_del(&StateContext->in_node);
					tcp_list.size--;
					kfree(StateContext);
				}
				break;
			}
		}
	}
	
	if (retport == 0) // No existing map, generate new map
	{
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
			
			if (tcp_list.last_alloc != 0) {
				rover_j = tcp_list.last_alloc / ratio / adjacent;
				rover_k = tcp_list.last_alloc % adjacent + 1;
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
				if (!tcp_port_in_use(retport))
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
				spin_unlock_bh(&tcp_list.lock);
#ifdef IVI_DEBUG_MAP
				printk(KERN_INFO "get_outflow_tcp_map_port: failed to assign a new map port for %d\n", oldp);
#endif
				return -1;
			}
		}
		
		// Now we have a mapped port allocated.
		// Create packet state and add mapping info to state list.
		StateContext = (PTCP_STATE_CONTEXT)kmalloc(sizeof(TCP_STATE_CONTEXT), GFP_ATOMIC);
		if (StateContext == NULL) {
			// No memory for state info. Fail this map.
			spin_unlock_bh(&tcp_list.lock);
#ifdef IVI_DEBUG_MAP
			printk(KERN_DEBUG "get_outflow_tcp_map_port: kmalloc failed for map %d\n", oldp);
#endif
			return -1;
		}
		memset(StateContext, 0, sizeof(TCP_STATE_CONTEXT));
		
		// Check packet state for new mapping.
		ftState = CreateTcpStateContext(th, len, StateContext);
		
		if (ftState == FILTER_DROP_CLEAN) {
			spin_unlock_bh(&tcp_list.lock);
#ifdef IVI_DEBUG_MAP
			printk(KERN_DEBUG "get_outflow_tcp_map_port: Invalid state on %d, TCP state %d, fail to add new map.\n", 
				oldp, StateContext->Status);
#endif
			kfree(StateContext);
			return -1;
		}
		
		// Routine to add new map-info
		StateContext->oldport = oldp;
		StateContext->newport = retport;
		StateContext->xlated = xlated;
		hash = port_hashfn(oldp);
		hlist_add_head(&StateContext->out_node, &tcp_list.out_chain[hash]);
		hash = port_hashfn(retport);
		hlist_add_head(&StateContext->in_node, &tcp_list.in_chain[hash]);
		tcp_list.size++;
		tcp_list.last_alloc = retport;
#ifdef IVI_DEBUG_MAP
		printk(KERN_DEBUG "get_outflow_tcp_map_port: New map %d -> %d added, TCP state %d, xlated = %d\n", 
			StateContext->oldport, StateContext->newport, StateContext->Status, StateContext->xlated);
#endif
	}
	
	spin_unlock_bh(&tcp_list.lock);
	
	*newp = retport;
	
	return (retport == 0 ? -1 : 0);
}
EXPORT_SYMBOL(get_outflow_tcp_map_port);

int get_inflow_tcp_map_port(__be16 newp, struct tcphdr *th, __u32 len, bool *xlated, __be16 *oldp)
{
	FILTER_STATUS       ftState;
	PTCP_STATE_CONTEXT  StateContext = NULL;
	struct hlist_node  *loop;
	struct hlist_node  *temp;
	int ret, hash;
	
	ret = -1;
	
	refresh_tcp_map_list();

	if (!xlated || !oldp)
		return -1;
	
	*oldp = 0;
	*xlated = false;
	
	spin_lock_bh(&tcp_list.lock);

	hash = port_hashfn(newp);
	if (hlist_empty(&tcp_list.in_chain[hash])) {
		spin_unlock_bh(&tcp_list.lock);
#ifdef IVI_DEBUG_MAP
		printk(KERN_INFO "get_inflow_tcp_map_port: in_chain[%d] empty.\n", hash);
#endif
		return -1;
	}
	
	hlist_for_each_entry_safe(StateContext, loop, temp, &tcp_list.in_chain[hash], in_node) {
		if (StateContext->newport == newp)  // Found existing mapping info
		{
			// Update state context.
			ftState = UpdateTcpStateContext(th, len, PACKET_DIR_REMOTE, StateContext);
			
			if (ftState == FILTER_ACCEPT) {
				*oldp = StateContext->oldport;
				*xlated = StateContext->xlated;
				ret = 0;
#ifdef IVI_DEBUG_MAP
				printk(KERN_DEBUG "get_inflow_tcp_map_port: Found map %d -> %d on in_chain[%d], TCP state %d, xlated = %d\n", 
					StateContext->oldport, StateContext->newport, hash, StateContext->Status, StateContext->xlated);
#endif
			}
			else if (ftState == FILTER_DROP) {
				// Return -1 to drop current segment but keep the state info.
#ifdef IVI_DEBUG_MAP
				printk(KERN_DEBUG "get_inflow_tcp_map_port: Invalid packet on map %d -> %d on in_chain[%d], TCP state %d, xlated = %d\n", 
					StateContext->oldport, StateContext->newport, hash, StateContext->Status, StateContext->xlated);
#endif
			}
			else  // FILTER_DROP_CLEAN
			{
#ifdef IVI_DEBUG_MAP
				printk(KERN_DEBUG "get_inflow_tcp_map_port: Invalid state on map %d -> %d on in_chain[%d], TCP state %d, xlated = %d\n", 
					StateContext->oldport, StateContext->newport, hash, StateContext->Status, StateContext->xlated);
#endif
				// Remove state info and return -1 to drop current segment
				hlist_del(&StateContext->out_node);
				hlist_del(&StateContext->in_node);
				tcp_list.size--;
				kfree(StateContext);
			}
			break;
		}
	}
	
	spin_unlock_bh(&tcp_list.lock);
	
	return ret;
}
EXPORT_SYMBOL(get_inflow_tcp_map_port);

#else

void init_tcp_map_list(void)
{
	spin_lock_init(&tcp_list.lock);
	INIT_LIST_HEAD(&tcp_list.chain);
	tcp_list.size = 0;
	tcp_list.last_alloc = 0;
}
EXPORT_SYMBOL(init_tcp_map_list);

// Refresh the timer for each map_tuple, must NOT acquire spin lock when calling this function
void refresh_tcp_map_list(void)
{
	PTCP_STATE_CONTEXT iter;
	PTCP_STATE_CONTEXT temp;
	struct timeval now;
	time_t delta;
	do_gettimeofday(&now);
	
	spin_lock_bh(&tcp_list.lock);
	list_for_each_entry_safe(iter, temp, &tcp_list.chain, node) {
		delta = now.tv_sec - iter->StateSetTime.tv_sec;
		if (delta >= iter->StateTimeOut) {
			list_del(&iter->node);
			tcp_list.size--;
#ifdef IVI_DEBUG_MAP
			printk(KERN_DEBUG "refresh_tcp_map_list: map %d -> %d time out on TCP state %d, xlated = %d\n", 
					iter->oldport, iter->newport, iter->Status, iter->xlated);
#endif
			kfree(iter);
		}
	}
	spin_unlock_bh(&tcp_list.lock);
}
EXPORT_SYMBOL(refresh_tcp_map_list);

// Clear the entire list, must NOT acquire spin lock when calling this function
void free_tcp_map_list(void)
{
	PTCP_STATE_CONTEXT iter;
	PTCP_STATE_CONTEXT temp;
	
	spin_lock_bh(&tcp_list.lock);
	list_for_each_entry_safe(iter, temp, &tcp_list.chain, node) {
		list_del(&iter->node);
		tcp_list.size--;
#ifdef IVI_DEBUG_MAP
		printk(KERN_DEBUG "free_tcp_map_list: map %d -> %d deleted on TCP state %d, xlated = %d\n", 
				iter->oldport, iter->newport, iter->Status, iter->xlated);
#endif
		kfree(iter);
	}
	spin_unlock_bh(&tcp_list.lock);
}
EXPORT_SYMBOL(free_tcp_map_list);

// Check whether a port is in use now, must be protected by spin lock when calling this function
static __inline int tcp_port_in_use(__be16 port)
{
	int ret = 0;

	if (!list_empty(&tcp_list.chain)) {
		PTCP_STATE_CONTEXT iter;
		list_for_each_entry(iter, &tcp_list.chain, node) {
			if (iter->newport == port) {
				ret = 1;
				break;
			}
		}
	}

	return ret;
}

int get_outflow_tcp_map_port(__be16 oldp, u16 ratio, u16 adjacent, u16 offset, struct tcphdr *th, __u32 len, bool xlated, __be16 *newp)
{
	__be16 retport = 0;
	
	PTCP_STATE_CONTEXT StateContext = NULL;
	FILTER_STATUS ftState;

	refresh_tcp_map_list();

	if (!newp)
		return -1;
	
	*newp = 0;
	
	spin_lock_bh(&tcp_list.lock);
    
	if (tcp_list.size >= (int)(64513 / ratio)) {
		spin_unlock_bh(&tcp_list.lock);
#ifdef IVI_DEBUG_MAP
		printk(KERN_INFO "get_outflow_tcp map_port: map list full.\n");
#endif
		return -1;
	}
	
	if (!list_empty(&tcp_list.chain)) {
		FILTER_STATUS       ftState;
        	PTCP_STATE_CONTEXT  StateContext;
        	PTCP_STATE_CONTEXT  temp;
		list_for_each_entry_safe(StateContext, temp, &tcp_list.chain, node) {
			if (StateContext->oldport == oldp) {
				// Update state context.
				ftState = UpdateTcpStateContext(th, len, PACKET_DIR_LOCAL, StateContext);
				
                		if (ftState == FILTER_ACCEPT) {
					retport = StateContext->newport;
#ifdef IVI_DEBUG_MAP
					printk(KERN_DEBUG "get_outflow_tcp_map_port: Found map %d -> %d, TCP state %d, xlated = %d\n", 
						StateContext->oldport, StateContext->newport, StateContext->Status, StateConext->xlated);
#endif
				}
				else if (ftState == FILTER_DROP) {
					// Return -1 to drop current segment, keep the state info.
#ifdef IVI_DEBUG_MAP
					printk(KERN_DEBUG "get_outflow_tcp_map_port: Invalid packet on map %d -> %d, TCP state %d, xlated = %d\n", 
						StateContext->oldport, StateContext->newport, StateContext->Status, StateConext->xlated);
#endif
				}
				else  // FILTER_DROP_CLEAN
				{
#ifdef IVI_DEBUG_MAP
					printk(KERN_DEBUG "get_outflow_tcp_map_port: Invalid state on map %d -> %d, TCP state %d, xlated = %d\n", 
						StateContext->oldport, StateContext->newport, StateContext->Status, StateConext->xlated);
#endif
					// Remove state info, return -1
					list_del(&StateContext->node);
					tcp_list.size--;
					kfree(StateContext);
				}
				break;
			}
		}
	}
	
	if (retport == 0) // No existing map, generate new map
	{
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
			
			if (tcp_list.last_alloc != 0) {
				rover_j = tcp_list.last_alloc / ratio / adjacent;
				rover_k = tcp_list.last_alloc % adjacent + 1;
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
				if (!tcp_port_in_use(retport))
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
				spin_unlock_bh(&tcp_list.lock);
#ifdef IVI_DEBUG_MAP
				printk(KERN_INFO "get_outflow_tcp_map_port: failed to assign a new map port for %d\n", oldp);
#endif
				return -1;
			}
		}
		
		// Now we have a mapped port allocated.
		// Create packet state and add mapping info to state list.
		StateContext = (PTCP_STATE_CONTEXT)kmalloc(sizeof(TCP_STATE_CONTEXT), GFP_ATOMIC);
		if (StateContext == NULL) {
			// No memory for state info. Fail this map.
			spin_unlock_bh(&tcp_list.lock);
#ifdef IVI_DEBUG_MAP
			printk(KERN_DEBUG "get_outflow_tcp_map_port: kmalloc failed for map %d\n", oldp);
#endif
			return -1;
		}
		memset(StateContext, 0, sizeof(TCP_STATE_CONTEXT));
		
		// Check packet state for new mapping.
		ftState = CreateTcpStateContext(th, len, StateContext);
		
		if (ftState == FILTER_DROP_CLEAN) {
			spin_unlock_bh(&tcp_list.lock);
#ifdef IVI_DEBUG_MAP
			printk(KERN_DEBUG "get_outflow_tcp_map_port: Invalid state on %d, TCP state %d, fail to add new map.\n", 
				oldp, StateContext->Status);
#endif
			kfree(StateContext);
			return -1;
		}
		
		// Routine to add new map-info
		StateContext->oldport = oldp;
		StateContext->newport = retport;
		StateConext->xlated = xlated;
		list_add(&StateContext->node, &tcp_list.chain);
		tcp_list.size++;
		tcp_list.last_alloc = retport;
#ifdef IVI_DEBUG_MAP
		printk(KERN_DEBUG "get_outflow_tcp_map_port: New map %d -> %d added, TCP state %d, xlated = %d\n", 
			StateContext->oldport, StateContext->newport, StateContext->Status, StateConext->xlated);
#endif
	}
	
	spin_unlock_bh(&tcp_list.lock);
	
	*newp = retport;
	
	return (retport == 0 ? -1 : 0);
}
EXPORT_SYMBOL(get_outflow_tcp_map_port);

int get_inflow_tcp_map_port(__be16 newp, struct tcphdr *th, __u32 len, bool *xlated, __be16 *oldp)
{
	FILTER_STATUS       ftState;
	PTCP_STATE_CONTEXT  StateContext = NULL;
	PTCP_STATE_CONTEXT  temp;
	
	int ret = -1;
	
	refresh_tcp_map_list();

	if (!xlated || !oldp)
		return -1;
	
	*oldp = 0;
	*xlated = false;
	
	spin_lock_bh(&tcp_list.lock);
	
	if (list_empty(&tcp_list.chain)) {
		spin_unlock_bh(&tcp_list.lock);
#ifdef IVI_DEBUG_MAP
		printk(KERN_INFO "get_inflow_tcp_map_port: map list empty.\n");
#endif
		return -1;
	}
	
	list_for_each_entry_safe(StateContext, temp, &tcp_list.chain, node) {
		if (StateContext->newport == newp)  // Found existing mapping info
		{
			// Update state context.
			ftState = UpdateTcpStateContext(th, len, PACKET_DIR_REMOTE, StateContext);
			
			if (ftState == FILTER_ACCEPT) {
				*oldp = StateContext->oldport;
				*xlated = StateConext->xlated;
				ret = 0;
#ifdef IVI_DEBUG_MAP
				printk(KERN_DEBUG "get_inflow_tcp_map_port: Found map %d -> %d, TCP state %d, xlated = %d\n", 
					StateContext->oldport, StateContext->newport, StateContext->Status, StateConext->xlated);
#endif
			}
			else if (ftState == FILTER_DROP) {
				// Return -1 to drop current segment but keep the state info.
#ifdef IVI_DEBUG_MAP
				printk(KERN_DEBUG "get_inflow_tcp_map_port: Invalid packet on map %d -> %d, TCP state %d, xlated = %d\n", 
					StateContext->oldport, StateContext->newport, StateContext->Status, StateConext->xlated);
#endif
			}
			else  // FILTER_DROP_CLEAN
			{
#ifdef IVI_DEBUG_MAP
				printk(KERN_DEBUG "get_inflow_tcp_map_port: Invalid state on map %d -> %d, TCP state %d, xlated = %d\n", 
					StateContext->oldport, StateContext->newport, StateContext->Status, StateConext->xlated);
#endif
				// Remove state info and return -1 to drop current segment
				list_del(&StateContext->node);
				tcp_list.size--;
				kfree(StateContext);
			}
			break;
		}
	}
	
	spin_unlock_bh(&tcp_list.lock);
	
	return ret;
}
EXPORT_SYMBOL(get_inflow_tcp_map_port);

#endif


static int __init ivi_map_tcp_init(void) {
#ifdef IVI_HASH
	printk(KERN_INFO "IVI: module ivi_map_tcp use hash list.\n");
#endif
	init_tcp_map_list();
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "IVI: module ivi_map_tcp loaded.\n");
#endif 
	return 0;
}
module_init(ivi_map_tcp_init);

static void __exit ivi_map_tcp_exit(void) {
	free_tcp_map_list();
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "IVI: module ivi_map_tcp unloaded.\n");
#endif
}
module_exit(ivi_map_tcp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wentao Shang <wentaoshang@gmail.com>");
MODULE_DESCRIPTION("IVI NAT44 Address TCP Port Mapping Kernel Module");
