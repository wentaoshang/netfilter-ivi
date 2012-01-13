/*
 * ivi_config.h :
 *  IVI Compile-Time Configuration File
 *
 */

#ifndef IVI_CONFIG_H
#define IVI_CONFIG_H

#define ADDR_FMT_NONE       0   // 1:1 xlate format
#define ADDR_FMT_POSTFIX    1   // 1:N old format, append ratio and offset at the end of the IPv6 address
#define ADDR_FMT_SUFFIX     2   // 1:N new format, append compressed ratio and offset code at the tail of the embed IPv4 address

#ifdef __KERNEL__

// comment this line out if you don't want to track any debug information
#define IVI_DEBUG

// comment this line out if you don't want to track any debug information of tcp connection state
//#define IVI_DEBUG_TCP

// comment this line out if you don't want to track any debug information of rule mapping
//#define IVI_DEBUG_RULE

// comment this line out if you don't want to track any debug information of port mapping
//#define IVI_DEBUG_MAP

#define IVI_MODE_CORE           0   // Stateless core translator
#define IVI_MODE_CORE_STATEFUL  1   // Stateful core translator (partial-state)
#define IVI_MODE_HGW            2   // Home gateway
#define IVI_MODE_HGW_NAT44      3   // Home gateway with NAT44

#ifndef NIP4
#define NIP4(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]
#define NIP4_FMT "%u.%u.%u.%u"
#endif

#ifndef NIP6
#define NIP6(addr) \
	ntohs((addr).s6_addr16[0]), \
	ntohs((addr).s6_addr16[1]), \
	ntohs((addr).s6_addr16[2]), \
	ntohs((addr).s6_addr16[3]), \
	ntohs((addr).s6_addr16[4]), \
	ntohs((addr).s6_addr16[5]), \
	ntohs((addr).s6_addr16[6]), \
	ntohs((addr).s6_addr16[7])
#define NIP6_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
#endif

// comment this line out if you want to use linked lists for port mapping
#define IVI_HASH

#ifdef IVI_HASH
#define IVI_HTABLE_SIZE		32
#define GOLDEN_RATIO_16		0x9e37
#define GOLDEN_RATIO_32		0x9e370001

// Generic hash function for a 16 bit value, see 'Introduction to Algorithms, 2nd Edition' Section 11.3.2
static inline int port_hashfn(__be16 port)
{
	unsigned int m = port * GOLDEN_RATIO_16;
	return ((m & 0xf800) >> 11);  // extract highest 5 bits as hash result
}

// Generic hash function for a 32 bit value, see 'Introduction to Algorithms, 2nd Edition' Section 11.3.2
static inline int v4addr_port_hashfn(__be32 addr, __be16 port)
{
	__be32 m = addr + port;
	m *= GOLDEN_RATIO_32;
	return ((m & 0xf8000000) >> 27);
}
#endif

#endif /* __KERNEL__ */

#endif /* IVI_CONFIG_H */
