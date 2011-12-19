/*
 * ivi_config.h :
 *  IVI Compile-Time Configuration File
 *
 */

#ifndef IVI_CONFIG_H
#define IVI_CONFIG_H

// comment this line out if you don't want to track any debug information of packet processing
#define IVI_DEBUG

// comment this line out if you don't want to track any debug information of tcp connection state
//#define IVI_DEBUG_TCP

// comment this line out if you don't want to track any debug information of rule mapping
//#define IVI_DEBUG_RULE

// comment this line out if you don't want to track any debug information of port mapping
//#define IVI_DEBUG_MAP

#define ADDR_FMT_NONE       0   // 1:1 xlate format
#define ADDR_FMT_POSTFIX    1   // 1:N old format, append ratio and offset at the end of the IPv6 address
#define ADDR_FMT_SUFFIX     2   // 1:N new format, append compressed ratio and offset code at the tail of the embed IPv4 address


// comment this line out if you want to use linked lists for port mapping
#define IVI_HASH

#ifdef IVI_HASH
#define IVI_HTABLE_SIZE		32
#define GOLDEN_RATIO_16		0x9e37
#define GOLDEN_RATIO_32		0x9e370001
#endif

#endif /* IVI_CONFIG_H */
