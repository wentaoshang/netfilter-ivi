#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include "../modules/ivi_ioctl.h"

struct rule_info {
	unsigned int prefix4;
	int plen4;
	struct in6_addr prefix6;
	int plen6;
	unsigned short ratio;
	unsigned short adjacent;
	unsigned char format;
};

static int disable_gso(const char *devname) {
	struct ifreq ifr;
	struct ethtool_value eval;
	int fd;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, devname);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		printf("Error: cannot get device control socket.\n");
		return -1;
	}

	// Disable gso
	eval.cmd = ETHTOOL_SGSO;
	eval.data = 0;
	ifr.ifr_data = (caddr_t)&eval;
	if (ioctl(fd, SIOCETHTOOL, &ifr)) {
		printf("Error: failed to disable gso on device %s.\n", devname);
		return -1;
	}

	// Disable tso
	eval.cmd = ETHTOOL_STSO;
	eval.data = 0;
	ifr.ifr_data = (caddr_t)&eval;
	if (ioctl(fd, SIOCETHTOOL, &ifr)) {
		printf("Error: failed to disable tso on device %s.\n", devname);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[]) {
	int retval, fd, temp;
	int mask;
	struct rule_info rule;
	char dev[IFNAMSIZ];

	if ((fd = open("/dev/ivi", 0)) < 0) {
		printf("Error: cannot open virtual device for ioctl, code %d.\n", fd);
		exit(-1);
	}

	if ((argc == 3) && (strcmp(argv[1], "device") == 0)) {
		strncpy(dev, argv[2], IFNAMSIZ);
		if ((retval = disable_gso(dev)) != 0) {
			printf("Error: failed to configure device %s.\n", dev);
			exit(-1);
		}
		printf("Info: successfully disabled gso & tso on device %s.\n", dev);
	}
	else if ((argc == 6) && (strcmp(argv[1], "start") == 0)) {
		memset(&rule, 0, sizeof(rule));
		// Set v4 network
		if ((retval = inet_pton(AF_INET, argv[2], (void*)(&(rule.prefix4)))) != 1) {
			printf("Error: failed to parse IPv4 address, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_V4NET, &(rule.prefix4))) < 0) {
			printf("Error: failed to assign IPv4 address, code %d.\n", retval);
			exit(-1);
		}
		rule.plen4 = atoi(argv[3]);
		mask = (rule.plen4 == 0) ? 0 : 0xffffffff << (32 - rule.plen4);
		if ((retval = ioctl(fd, IVI_IOC_V4MASK, &(mask))) < 0) {
			printf("Error: failed to assign IPv4 network prefix length, code %d.\n", retval);
			exit(-1);
		}
		
		// Set v6 network
		if ((retval = inet_pton(AF_INET6, argv[4], (void*)(&(rule.prefix6)))) != 1) {
			printf("Error: failed to parse IPv6 network prefix, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_V6NET, &(rule.prefix6))) < 0) {
			printf("Error: failed to assign IPv6 network prefix, code %d.\n", retval);
			exit(-1);
		}
		rule.plen6 = atoi(argv[5]);
		temp = rule.plen6 >> 3;  // counted in bytes
		if ((retval = ioctl(fd, IVI_IOC_V6MASK, &temp)) < 0) {
			printf("Error: failed to assign IPv6 network prefix length, code %d.\n", retval);
			exit(-1);
		}

		// Insert default prefix mapping rule
		rule.prefix4 = 0;
		rule.plen4 = 0;
		rule.format = ADDR_FMT_NONE;
		if ((retval = ioctl(fd, IVI_IOC_ADD_RULE, &rule)) < 0) {
			printf("Error: failed to add default prefix mapping rule, code %d.\n", retval);
			exit(-1);
		}
		
		// Start ivi
		if ((retval = ioctl(fd, IVI_IOC_START, 0)) < 0) {
			printf("Error: failed to start IVI module, code %d.\n", retval);
			exit(-1);
		}
		
		printf("Info: successfully started IVI module.\n");
	}
	else if ((argc == 8) && (strcmp(argv[1], "start") == 0)) {
		memset(&rule, 0, sizeof(rule));
		// Set v4 network
		if ((retval = inet_pton(AF_INET, argv[2], (void*)(&(rule.prefix4)))) != 1) {
			printf("Error: failed to parse IPv4 address, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_V4NET, &(rule.prefix4))) < 0) {
			printf("Error: failed to assign IPv4 address, code %d.\n", retval);
			exit(-1);
		}
		rule.plen4 = atoi(argv[3]);
		mask = (rule.plen4 == 0) ? 0 : 0xffffffff << (32 - rule.plen4);
		if ((retval = ioctl(fd, IVI_IOC_V4MASK, &(mask))) < 0) {
			printf("Error: failed to assign IPv4 network prefix length, code %d.\n", retval);
			exit(-1);
		}
		
		// Set v6 network
		if ((retval = inet_pton(AF_INET6, argv[4], (void*)(&(rule.prefix6)))) != 1) {
			printf("Error: failed to parse IPv6 network prefix, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_V6NET, &(rule.prefix6))) < 0) {
			printf("Error: failed to assign IPv6 network prefix, code %d.\n", retval);
			exit(-1);
		}
		rule.plen6 = atoi(argv[5]);
		temp = rule.plen6 >> 3;  /* counted in bytes */
		if ((retval = ioctl(fd, IVI_IOC_V6MASK, &temp)) < 0) {
			printf("Error: failed to assign IPv6 network prefix length, code %d.\n", retval);
			exit(-1);
		}
/*
		// Insert local rule
		rule.prefix4 = ntohl(rule.prefix4);
		rule.prefix4 = rule.prefix4 & mask;
		rule.format = ADDR_FMT_SUFFIX;
		if ((retval = ioctl(fd, IVI_IOC_ADD_RULE, &rule)) < 0) {
			printf("Error: failed to add prefix mapping rule, code %d.\n", retval);
			exit(-1);
		}
*/
		memset(&rule, 0, sizeof(rule));
		// Set v6 default prefix
		if ((retval = inet_pton(AF_INET6, argv[6], (void*)(&(rule.prefix6)))) != 1) {
			printf("Error: failed to parse IPv6 network prefix, code %d.\n", retval);
			exit(-1);
		}
		rule.plen6 = atoi(argv[5]);
		rule.format = ADDR_FMT_NONE;

		// Insert default prefix mapping rule
		if ((retval = ioctl(fd, IVI_IOC_ADD_RULE, &rule)) < 0) {
			printf("Error: failed to add default prefix mapping rule, code %d.\n", retval);
			exit(-1);
		}
		
		// Start ivi
		if ((retval = ioctl(fd, IVI_IOC_START, 0)) < 0) {
			printf("Error: failed to start IVI module, code %d.\n", retval);
			exit(-1);
		}
		
		printf("Info: successfully started IVI module.\n");
	}
	else if ((argc == 2) && (strcmp(argv[1], "stop") == 0)) {
		if ((retval = ioctl(fd, IVI_IOC_STOP, 0)) != 0) {
			printf("Error: failed to stop IVI module, code %d.\n", retval);
		}
		else {
			printf("Info: successfully stopped IVI module.\n");
		}
	}
	else if ((argc == 5) && (strcmp(argv[1], "format") == 0)) {
		unsigned short postfix[2];
		unsigned short adjacent;
		postfix[0] = atoi(argv[3]);
		postfix[1] = atoi(argv[4]);
		adjacent = 1;
		if (strcmp(argv[2], "postfix") == 0) {
			if ((retval = ioctl(fd, IVI_IOC_POSTFIX, postfix)) < 0) {
				printf("Error: failed to set addr format, code %d.\n", retval);
				exit(-1);
			}
			if ((retval = ioctl(fd, IVI_IOC_ADJACENT, (void*)(&adjacent))) < 0) {
				printf("Error: failed to set adjacent parameter, code %d.\n", retval);
				exit(-1);
			}
		}
		else if (strcmp(argv[2], "suffix") == 0) {
			if ((retval = ioctl(fd, IVI_IOC_SUFFIX, postfix)) < 0) {
				printf("Error: failed to set addr format, code %d.\n", retval);
				exit(-1);
			}
			if ((retval = ioctl(fd, IVI_IOC_ADJACENT, (void*)(&adjacent))) < 0) {
				printf("Error: failed to set adjacent parameter, code %d.\n", retval);
				exit(-1);
			}
		}
		else {
			printf("Error: unknown address format name %s.\n", argv[2]);
			exit(-1);
		}
		printf("Info: successfully set address format.\n");
	}
	else if ((argc == 6) && (strcmp(argv[1], "format") == 0)) {
		unsigned short postfix[2];
		unsigned short adjacent;
		postfix[0] = atoi(argv[3]);
		postfix[1] = atoi(argv[4]);
		adjacent = atoi(argv[5]);
		if (strcmp(argv[2], "suffix") == 0) {
			if ((retval = ioctl(fd, IVI_IOC_SUFFIX, postfix)) < 0) {
				printf("Error: failed to set addr format, code %d.\n", retval);
				exit(-1);
			}
			if ((retval = ioctl(fd, IVI_IOC_ADJACENT, (void*)(&adjacent))) < 0) {
				printf("Error: failed to set adjacent parameter, code %d.\n", retval);
				exit(-1);
			}
		}
		else {
			printf("Error: unknown address format name %s.\n", argv[2]);
			exit(-1);
		}
		printf("Info: successfully set address format.\n");
	}
	else if ((argc == 4) && (strcmp(argv[1], "mss") == 0)) {
		unsigned short mss_val;
		mss_val = atoi(argv[3]);
		if (strcmp(argv[2], "limit") == 0) {
			if ((retval = ioctl(fd, IVI_IOC_MSS_LIMIT, (void*)(&mss_val))) < 0) {
				printf("Error: failed to set mss limit, code %d.\n", retval);
				exit(-1);
			}
		}
		else {
			printf("Error: unknown mss option type %s.\n", argv[2]);
			exit(-1);
		}
		printf("Info: successfully set mss.\n");
	}
	else if ((argc == 6) && (strcmp(argv[1], "rule") == 0)) {
		memset(&rule, 0, sizeof(rule));
		
		if (strcmp(argv[2], "add") == 0 && strcmp(argv[3], "default") == 0) {
			rule.prefix4 = 0;
			rule.plen4 = 0;
		
			if ((retval = inet_pton(AF_INET6, argv[4], (void*)(&(rule.prefix6)))) != 1) {
				printf("Error: failed to parse IPv6 network prefix, code %d.\n", retval);
				exit(-1);
			}
			rule.plen6 = atoi(argv[5]);
			rule.ratio = 1;
			rule.adjacent = 1;

			// Insert rule
			if ((retval = ioctl(fd, IVI_IOC_ADD_RULE, &rule)) < 0) {
				printf("Error: failed to add prefix mapping rule, code %d.\n", retval);
				exit(-1);
			}
			printf("Info: successfully add rule.\n");
		} else {
			printf("Error: unknown rule command '%s'.\n", argv[2]);
			exit(-1);
		}
	}
	else if ((argc == 9) && (strcmp(argv[1], "rule") == 0)) {
		memset(&rule, 0, sizeof(rule));
		
		if (strcmp(argv[2], "add") == 0) {
			if ((retval = inet_pton(AF_INET, argv[3], (void*)(&(rule.prefix4)))) != 1) {
				printf("Error: failed to parse IPv4 prefix, code %d.\n", retval);
				exit(-1);
			}
			rule.plen4 = atoi(argv[4]);
			mask = (rule.plen4 == 0) ? 0 : 0xffffffff << (32 - rule.plen4);
			rule.prefix4 = ntohl(rule.prefix4);
			rule.prefix4 = rule.prefix4 & mask;
		
			if ((retval = inet_pton(AF_INET6, argv[5], (void*)(&(rule.prefix6)))) != 1) {
				printf("Error: failed to parse IPv6 network prefix, code %d.\n", retval);
				exit(-1);
			}
			rule.plen6 = atoi(argv[6]);
			rule.ratio = atoi(argv[7]);
			rule.adjacent = atoi(argv[8]);
			rule.format = ADDR_FMT_SUFFIX;

			// Insert rule
			if ((retval = ioctl(fd, IVI_IOC_ADD_RULE, &rule)) < 0) {
				printf("Error: failed to add prefix mapping rule, code %d.\n", retval);
				exit(-1);
			}
			printf("Info: successfully add rule.\n");
		} else {
			printf("Error: unknown rule command '%s'.\n", argv[2]);
			exit(-1);
		}
	}
	else {
		printf("IVI netfilter device controller utility v1.3\n");
		printf("\n");
		printf("Usage: ivictl start [v4_host_addr] [v4_prefix_len] [v6_prefix] [v6_prefix_len]\n");
		printf("       ivictl start [v4_host_addr] [v4_prefix_len] [v6_prefix] [v6_prefix_len] [default_prefix] [default_prefix_len]\n");
		printf("       ivictl format postfix [ratio] [offset]\n");
		printf("       ivictl format suffix [ratio] [offset]\n");
		printf("       ivictl format suffix [ratio] [offset] [adjacent]\n");
		printf("       ivictl mss limit [mss_val]\n");
		printf("       ivictl rule add default [v6_prefix] [v6_prefix_len]\n");
		printf("       ivictl rule add [v4_prefix] [v4_prefix_len] [v6_prefix] [v6_prefix_len] [ratio] [adjacent]\n");
		printf("       ivictl device [dev_name]\n");
		printf("       ivictl stop\n");
	}

	close(fd);

	return retval;
}
