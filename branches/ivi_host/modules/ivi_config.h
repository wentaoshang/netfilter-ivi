/*
 * ivi_config.h :
 *  IVI Compile-Time Configuration File
 *
 */

#ifndef IVI_CONFIG_H
#define IVI_CONFIG_H

// comment this line out if you don't want to track any debug information
#define IVI_DEBUG

// comment this line out if you don't want to track any debug information of tcp connection state
//#define IVI_DEBUG_TCP

// comment this line out if you want to use linked lists for port mapping
#define IVI_HASH

#ifdef IVI_HASH
#define IVI_HTABLE_SIZE		32
#define GOLDEN_RATIO_16		0x9e37
#define GOLDEN_RATIO_32		0x9e370001
#endif

#endif /* IVI_CONFIG_H */