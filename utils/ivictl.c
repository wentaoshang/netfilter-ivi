#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "../modules/ivi_ioctl.h"

int main(int argc, char *argv[]) {
	char v4dev[IVI_IOCTL_LEN], v6dev[IVI_IOCTL_LEN];
	int retval, fd, temp;
	struct in_addr v4addr;
	int mask;
	struct in6_addr v6addr;
	
	printf("IVI netfilter device controller utility v1.3\n");
	
	if ((fd = open("/dev/ivi", 0)) < 0) {
		printf("Error: cannot open virtual device for ioctl, code %d.\n", fd);
		exit(-1);
	}

	if ((argc == 8) && (strcmp(argv[1], "start") == 0)) {
		// Set dev
		strncpy(v4dev, argv[2], IVI_IOCTL_LEN);
		strncpy(v6dev, argv[3], IVI_IOCTL_LEN);
		if ((retval = ioctl(fd, IVI_IOC_V4DEV, v4dev)) < 0) {
			printf("Error: failed to assign IPv4 device, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_V6DEV, v6dev)) < 0) {
			printf("Error: failed to assign IPv6 device, code %d.\n", retval);
			exit(-1);
		}
		
		// Set v4 network
		if ((retval = inet_pton(AF_INET, argv[4], (void*)(&v4addr))) != 1) {
			printf("Error: failed to parse IPv4 network prefix, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_V4NET, &(v4addr.s_addr))) < 0) {
			printf("Error: failed to assign IPv4 network prefix, code %d.\n", retval);
			exit(-1);
		}
		temp = atoi(argv[5]);
		mask = 0xffffffff << (32 - temp);
		if ((retval = ioctl(fd, IVI_IOC_V4MASK, &(mask))) < 0) {
			printf("Error: failed to assign IPv4 network prefix length, code %d.\n", retval);
			exit(-1);
		}
		
		// Set v6 network
		if ((retval = inet_pton(AF_INET6, argv[6], (void*)(&v6addr))) != 1) {
			printf("Error: failed to parse IPv6 network prefix, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_V6NET, v6addr.s6_addr)) < 0) {
			printf("Error: failed to assign IPv6 network prefix, code %d.\n", retval);
			exit(-1);
		}
		temp = atoi(argv[7]) / 8;  // counted in bytes
		if ((retval = ioctl(fd, IVI_IOC_V6MASK, &(temp))) < 0) {
			printf("Error: failed to assign IPv6 network prefix length, code %d.\n", retval);
			exit(-1);
		}

		// Set v6 default prefix
		if ((retval = ioctl(fd, IVI_IOC_PD_DEFAULT, v6addr.s6_addr)) < 0) {
			printf("Error: failed to assign IPv6 default prefix, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_PD_DEFAULT_LEN, &(temp))) < 0) {
			printf("Error: failed to assign IPv6 default prefix length, code %d.\n", retval);
			exit(-1);
		}

		// Start ivi
		if ((retval = ioctl(fd, IVI_IOC_NONAT, 0)) < 0) {
			printf("Error: failed to disable nat44, code %d.\n", retval);
			exit(-1);
		}
		
		if ((retval = ioctl(fd, IVI_IOC_START, 0)) < 0) {
			printf("Error: failed to start IVI module, code %d.\n", retval);
			exit(-1);
		}
		
		printf("Info: successfully started IVI module.\n");
	}
	else if ((argc == 9) && (strcmp(argv[1], "start") == 0)) {
		// Set dev
		strncpy(v4dev, argv[2], IVI_IOCTL_LEN);
		strncpy(v6dev, argv[3], IVI_IOCTL_LEN);
		if ((retval = ioctl(fd, IVI_IOC_V4DEV, v4dev)) < 0) {
			printf("Error: failed to assign IPv4 device, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_V6DEV, v6dev)) < 0) {
			printf("Error: failed to assign IPv6 device, code %d.\n", retval);
			exit(-1);
		}
		
		// Set v4 network
		if ((retval = inet_pton(AF_INET, argv[4], (void*)(&v4addr))) != 1) {
			printf("Error: failed to parse IPv4 network prefix, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_V4NET, &(v4addr.s_addr))) < 0) {
			printf("Error: failed to assign IPv4 network prefix, code %d.\n", retval);
			exit(-1);
		}
		temp = atoi(argv[5]);
		mask = 0xffffffff << (32 - temp);
		if ((retval = ioctl(fd, IVI_IOC_V4MASK, &(mask))) < 0) {
			printf("Error: failed to assign IPv4 network prefix length, code %d.\n", retval);
			exit(-1);
		}
		
		// Set v4 public address for nat44
		if ((retval = inet_pton(AF_INET, argv[6], (void*)(&v4addr))) != 1) {
			printf("Error: failed to parse IPv4 public address, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_V4PUB, &(v4addr.s_addr))) < 0) {
			printf("Error: failed to assign IPv4 public address, code %d.\n", retval);
			exit(-1);
		}
		
		// Set v6 network
		if ((retval = inet_pton(AF_INET6, argv[7], (void*)(&v6addr))) != 1) {
			printf("Error: failed to parse IPv6 network prefix, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_V6NET, v6addr.s6_addr)) < 0) {
			printf("Error: failed to assign IPv6 network prefix, code %d.\n", retval);
			exit(-1);
		}
		temp = atoi(argv[8]) / 8;  // counted in bytes
		if ((retval = ioctl(fd, IVI_IOC_V6MASK, &(temp))) < 0) {
			printf("Error: failed to assign IPv6 network prefix length, code %d.\n", retval);
			exit(-1);
		}

		// Set v6 default prefix
		if ((retval = ioctl(fd, IVI_IOC_PD_DEFAULT, v6addr.s6_addr)) < 0) {
			printf("Error: failed to assign IPv6 default prefix, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_PD_DEFAULT_LEN, &(temp))) < 0) {
			printf("Error: failed to assign IPv6 default prefix length, code %d.\n", retval);
			exit(-1);
		}

		// Start ivi
		if ((retval = ioctl(fd, IVI_IOC_NAT, 0)) < 0) {
			printf("Error: failed to enable nat44, code %d.\n", retval);
			exit(-1);
		}
		
		if ((retval = ioctl(fd, IVI_IOC_START, 0)) < 0) {
			printf("Error: failed to start IVI module, code %d.\n", retval);
			exit(-1);
		}
		
		printf("Info: successfully started IVI module.\n");
	}
	else if ((argc == 10) && (strcmp(argv[1], "start") == 0)) {
		// Set dev
		strncpy(v4dev, argv[2], IVI_IOCTL_LEN);
		strncpy(v6dev, argv[3], IVI_IOCTL_LEN);
		if ((retval = ioctl(fd, IVI_IOC_V4DEV, v4dev)) < 0) {
			printf("Error: failed to assign IPv4 device, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_V6DEV, v6dev)) < 0) {
			printf("Error: failed to assign IPv6 device, code %d.\n", retval);
			exit(-1);
		}
		
		// Set v4 network
		if ((retval = inet_pton(AF_INET, argv[4], (void*)(&v4addr))) != 1) {
			printf("Error: failed to parse IPv4 network prefix, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_V4NET, &(v4addr.s_addr))) < 0) {
			printf("Error: failed to assign IPv4 network prefix, code %d.\n", retval);
			exit(-1);
		}
		temp = atoi(argv[5]);
		mask = 0xffffffff << (32 - temp);
		if ((retval = ioctl(fd, IVI_IOC_V4MASK, &(mask))) < 0) {
			printf("Error: failed to assign IPv4 network prefix length, code %d.\n", retval);
			exit(-1);
		}
		
		// Set v6 network
		if ((retval = inet_pton(AF_INET6, argv[6], (void*)(&v6addr))) != 1) {
			printf("Error: failed to parse IPv6 network prefix, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_V6NET, v6addr.s6_addr)) < 0) {
			printf("Error: failed to assign IPv6 network prefix, code %d.\n", retval);
			exit(-1);
		}
		temp = atoi(argv[7]) / 8;  // counted in bytes
		if ((retval = ioctl(fd, IVI_IOC_V6MASK, &(temp))) < 0) {
			printf("Error: failed to assign IPv6 network prefix length, code %d.\n", retval);
			exit(-1);
		}
		
		// Set v6 default prefix
		if ((retval = inet_pton(AF_INET6, argv[8], (void*)(&v6addr))) != 1) {
			printf("Error: failed to parse IPv6 default prefix, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_PD_DEFAULT, v6addr.s6_addr)) < 0) {
			printf("Error: failed to assign IPv6 default prefix, code %d.\n", retval);
			exit(-1);
		}
		temp = atoi(argv[9]) / 8;  // counted in bytes
		if ((retval = ioctl(fd, IVI_IOC_PD_DEFAULT_LEN, &(temp))) < 0) {
			printf("Error: failed to assign IPv6 default prefix length, code %d.\n", retval);
			exit(-1);
		}
		
		// Start ivi
		if ((retval = ioctl(fd, IVI_IOC_NONAT, 0)) < 0) {
			printf("Error: failed to disable nat44, code %d.\n", retval);
			exit(-1);
		}
		
		if ((retval = ioctl(fd, IVI_IOC_START, 0)) < 0) {
			printf("Error: failed to start IVI module, code %d.\n", retval);
			exit(-1);
		}
		
		printf("Info: successfully started IVI module.\n");
	}
	else if ((argc == 11) && (strcmp(argv[1], "start") == 0)) {
		// Set dev
		strncpy(v4dev, argv[2], IVI_IOCTL_LEN);
		strncpy(v6dev, argv[3], IVI_IOCTL_LEN);
		if ((retval = ioctl(fd, IVI_IOC_V4DEV, v4dev)) < 0) {
			printf("Error: failed to assign IPv4 device, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_V6DEV, v6dev)) < 0) {
			printf("Error: failed to assign IPv6 device, code %d.\n", retval);
			exit(-1);
		}
		
		// Set v4 network
		if ((retval = inet_pton(AF_INET, argv[4], (void*)(&v4addr))) != 1) {
			printf("Error: failed to parse IPv4 network prefix, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_V4NET, &(v4addr.s_addr))) < 0) {
			printf("Error: failed to assign IPv4 network prefix, code %d.\n", retval);
			exit(-1);
		}
		temp = atoi(argv[5]);
		mask = 0xffffffff << (32 - temp);
		if ((retval = ioctl(fd, IVI_IOC_V4MASK, &(mask))) < 0) {
			printf("Error: failed to assign IPv4 network prefix length, code %d.\n", retval);
			exit(-1);
		}
		
		// Set v4 public address for nat44
		if ((retval = inet_pton(AF_INET, argv[6], (void*)(&v4addr))) != 1) {
			printf("Error: failed to parse IPv4 public address, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_V4PUB, &(v4addr.s_addr))) < 0) {
			printf("Error: failed to assign IPv4 public address, code %d.\n", retval);
			exit(-1);
		}
		
		// Set v6 network
		if ((retval = inet_pton(AF_INET6, argv[7], (void*)(&v6addr))) != 1) {
			printf("Error: failed to parse IPv6 network prefix, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_V6NET, v6addr.s6_addr)) < 0) {
			printf("Error: failed to assign IPv6 network prefix, code %d.\n", retval);
			exit(-1);
		}
		temp = atoi(argv[8]) / 8;  // counted in bytes
		if ((retval = ioctl(fd, IVI_IOC_V6MASK, &(temp))) < 0) {
			printf("Error: failed to assign IPv6 network prefix length, code %d.\n", retval);
			exit(-1);
		}
		
		// Set v6 default prefix
		if ((retval = inet_pton(AF_INET6, argv[9], (void*)(&v6addr))) != 1) {
			printf("Error: failed to parse IPv6 default prefix, code %d.\n", retval);
			exit(-1);
		}
		if ((retval = ioctl(fd, IVI_IOC_PD_DEFAULT, v6addr.s6_addr)) < 0) {
			printf("Error: failed to assign IPv6 default prefix, code %d.\n", retval);
			exit(-1);
		}
		temp = atoi(argv[10]) / 8;  // counted in bytes
		if ((retval = ioctl(fd, IVI_IOC_PD_DEFAULT_LEN, &(temp))) < 0) {
			printf("Error: failed to assign IPv6 default prefix length, code %d.\n", retval);
			exit(-1);
		}

		// Start ivi
		if ((retval = ioctl(fd, IVI_IOC_NAT, 0)) < 0) {
			printf("Error: failed to enable nat44, code %d.\n", retval);
			exit(-1);
		}
		
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
		postfix[0] = atoi(argv[3]);
		postfix[1] = atoi(argv[4]);
		if (strcmp(argv[2], "postfix") == 0) {
			if ((retval = ioctl(fd, IVI_IOC_POSTFIX, postfix)) < 0) {
				printf("Error: failed to set addr format, code %d.\n", retval);
				exit(-1);
			}
		}
		else if (strcmp(argv[2], "suffix") == 0) {
			if ((retval = ioctl(fd, IVI_IOC_SUFFIX, postfix)) < 0) {
				printf("Error: failed to set addr format, code %d.\n", retval);
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
	else {
		printf("Usage: ivictl start [v4_dev] [v6_dev] [v4_prefix] [v4_prefix_len] [v6_prefix] [v6_prefix_len]\n");
		printf("       ivictl start [v4_dev] [v6_dev] [v4_prefix] [v4_prefix_len] [v6_prefix] [v6_prefix_len] [default_prefix] [default_prefix_len]\n");
		printf("       ivictl start [v4_dev] [v6_dev] [v4_prefix] [v4_prefix_len] [v4_public_addr] [v6_prefix] [v6_prefix_len]\n");
		printf("       ivictl start [v4_dev] [v6_dev] [v4_prefix] [v4_prefix_len] [v4_public_addr] [v6_prefix] [v6_prefix_len] [default_prefix] [default_prefix_len]\n");
		printf("       ivictl format postfix [ratio] [offset]\n");
		printf("       ivictl format suffix [ratio] [offset]\n");
		printf("       ivictl mss limit [mss_val]\n");
		printf("       ivictl stop\n");
	}

	close(fd);

	return retval;
}
