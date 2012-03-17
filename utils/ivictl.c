#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <getopt.h>

#include "../modules/ivi_ioctl.h"

static const struct option longopts[] =
{
	{"rule", no_argument, NULL, 'r'},
	{"start", no_argument, NULL, 's'},
	{"stop", required_argument, NULL, 'q'},
	{"help", no_argument, NULL, 'h'},
	{"hgw", no_argument, NULL, 'H'},
	{"nat44", no_argument, NULL, 'N'},
	{"default", no_argument, NULL, 'd'},
	{"prefix4", required_argument, NULL, 'p'},
	{"prefix4len", required_argument, NULL, 'l'},
	{"prefix6", required_argument, NULL, 'P'},
	{"prefix6len",required_argument, NULL, 'L'},
	{"ratio", required_argument, NULL, 'R'},
	{"adjacent", required_argument, NULL, 'M'},
	{"format", required_argument, NULL, 'f'},
	{"offset", required_argument, NULL, 'o'},
	{"addr4", required_argument, NULL, 'a'},
	{"publicaddr4", required_argument, NULL, 'A'},
	{"dev4", required_argument, NULL, 'i'},
	{"dev6", required_argument, NULL, 'I'},
	{"mssclamping", required_argument, NULL, 'c'},
	{NULL, no_argument, NULL, 0}
};


static char hgw;
static char nat44;
static char dev[IVI_IOCTL_LEN];
static __u16 gma[2];  // Store R and PSID, M is stored in 'rule.adjacent'
static __u16 mss_val;
static struct in_addr v4addr;
static struct rule_info rule;

void usage(int status) {
	if (status != EXIT_SUCCESS)
		printf("Try `ivictl --help' for more information.\n");
	else {
		printf("\
Usage:  ivictl -r [rule_options]\n\
	(used to insert a mapping rule)\n\
	ivictl -s [start_options]\n\
	(user to start ivi module)\n\
	ivictl -q\n\
	(user to stop ivi module)\n\
\n\
rule_options:\n\
	-p --prefix4 PREFIX4\n\
		specify the ipv4 prefix\n\
	-P --prefix6 PREFIX6\n\
		specify the ipv6 prefix\n\
	-l --prefix4len [PREFIX4 LENGTH]\n\
		specify ipv4 prefix length\n\
	-L --prefix6len [PREFIX6 LENGTH]\n\
		specify the ipv6 prefix length\n\
	-R --ratio RATIO\n\
		specify the address sharing ratio in GMA\n\
	-M --adjacent ADJACENT\n\
		specify the M parameter in GMA\n\
	-f --format FORMAT\n\
		specify the address translation format (use 1:1 format if not specified)\n\
		currently available format:\n\
			postfix\n\
			suffix\n\
	-d --default\n\
		specify the ipv4 prefix is '0.0.0.0/0' instead of using '-p 0.0.0.0 -l 0'\n\
\n\
start_options:\n\
	-i --dev4 DEV4\n\
		specify the name of ipv4 device\n\
	-I --dev6 DEV6\n\
		specify the name of ipv6 device\n\
	-c --mssclamping MSS\n\
		specify the reduced tcp mss value\n\
\n\
	HGW mode:\n\
		-H --hgw\n\
			specify that IVI is working as home gateway\n\
		-N --nat44\n\
			specify that IVI HGW is performing NAT44\n\
		-o --offset OFFSET\n\
			specify the local offset of the HGW, default is 0\n\
		-p --prefix4 PREFIX4\n\
			specify the (private) ipv4 network prefix behind the HGW\n\
		-l --prefix4len [PREFIX4 LENGTH]\n\
			specify the mask length of the ipv4 network\n\
			refer to private network mask length in nat44 mode\n\
		-A --publicaddr4 PUBLICADDR4\n\
			specify the public ipv4 address used by the HGW\n\
			always used with -N (--nat44)\n\
		-P --prefix6 PREFIX6\n\
			specify the local IVI prefix used by the HGW\n\
		-L --prefix6len [PREFIX6 LENGTH]\n\
			specify the length of the local IVI prefix\n\
		-R --ratio RATIO\n\
			specify the local address sharing ratio in GMA\n\
		-M --adjacent ADJACENT\n\
			specify the local M parameter in GMA\n\
		-f --format FORMAT\n\
			specify the local address translation format (use 1:1 format if not specified)\n\
			currently available format:\n\
				postfix\n\
				suffix\n\
\n");
	}
	exit(status);
}

static inline void param_init(void) {
	hgw = 0;
	nat44 = 0;
	gma[0] = gma[1] = 0;
	memset(&rule, 0, sizeof(rule));
	rule.ratio = 1;
	rule.adjacent = 1;
	rule.format = ADDR_FMT_NONE;
}

int main(int argc, char *argv[]) {
	int retval, fd, temp, optc;
	
	printf("IVI netfilter device controller utility v1.4\n");
	
	if ((fd = open("/dev/ivi", 0)) < 0) {
		printf("Error: cannot open virtual device for ioctl, code %d.\n", fd);
		exit(-1);
	}
	
	param_init();
	
	optc = getopt_long(argc, argv, "rsqh", longopts, NULL);
	switch (optc) 
	{
		case 'r':
			goto rule_opt;
			break;
		case 's':
			goto start_opt;
			break;
		case 'q':
			if ((retval = ioctl(fd, IVI_IOC_STOP, 0)) != 0) {
				printf("Error: failed to stop IVI module, code %d.\n", retval);
			}
			else {
				printf("Info: successfully stopped IVI module.\n");
			}
			goto out;
			break;
		case 'h':
			close(fd);
			usage(EXIT_SUCCESS);
			break;
		default:
			close(fd);
			usage(EXIT_FAILURE);
			break;
	}
	
rule_opt:
	while ((optc = getopt_long(argc, argv, "p:P:l:L:R:M:f:d", longopts, NULL)) != -1)
	{
		switch(optc)
		{
			case 'd':
				rule.prefix4 = 0;
				rule.plen4 = 0;
				break;
			case 'p':
				if ((retval = inet_pton(AF_INET, optarg, (void*)(&(rule.prefix4)))) != 1) {
					printf("Error: failed to parse IPv4 prefix, code %d.\n", retval);
					retval = -1;
					goto out;
				}
				rule.prefix4 = ntohl(rule.prefix4);  // Convert to host byte order
				break;
			case 'l':
				rule.plen4 = atoi(optarg);
				break;
			case 'P':
				if ((retval = inet_pton(AF_INET6, optarg, (void*)(&(rule.prefix6)))) != 1) {
					printf("Error: failed to parse IPv6 prefix, code %d.\n", retval);
					retval = -1;
					goto out;
				}
				break;
			case 'L':
				rule.plen6 = atoi(optarg);
				break;
			case 'R':
				rule.ratio = atoi(optarg);
				break;
			case 'M':
				rule.adjacent = atoi(optarg);
				break;
			case 'f':
				if (strcmp(optarg, "postfix") == 0)
					rule.format = ADDR_FMT_POSTFIX;
				else if (strcmp(optarg, "suffix") == 0)
					rule.format = ADDR_FMT_SUFFIX;
				else {
					printf("Error: unknown format name %s. Must be 'postfix' or 'suffix'.\n", optarg);
					retval = -1;
					goto out;
				}
				break;
			default:
				close(fd);
				usage(EXIT_FAILURE);
				break;
		}
	}
	
	// Finalize
	temp = (rule.plen4 == 0) ? 0 : 0xffffffff << (32 - rule.plen4);  // Generate network mask
	rule.prefix4 = rule.prefix4 & temp;
	
	// Insert rule
	if ((retval = ioctl(fd, IVI_IOC_ADD_RULE, &rule)) < 0) {
		printf("Error: failed to add mapping rule, code %d.\n", retval);
	} else {
		printf("Info: successfully add mapping rule.\n");
	}
	
	goto out;


start_opt:
	while ((optc = getopt_long(argc, argv, "i:I:A:p:l:L:P:R:M:o:f:c:HN", longopts, NULL)) != -1)
	{
		switch(optc)
		{
			case 'i':
				strncpy(dev, optarg, IVI_IOCTL_LEN);
				if ((retval = ioctl(fd, IVI_IOC_V4DEV, dev)) < 0) {
					printf("Error: failed to assign IPv4 device, code %d.\n", retval);
					goto out;
				}
				break;
			case 'I':
				strncpy(dev, optarg, IVI_IOCTL_LEN);
				if ((retval = ioctl(fd, IVI_IOC_V6DEV, dev)) < 0) {
					printf("Error: failed to assign IPv6 device, code %d.\n", retval);
					goto out;
				}
				break;
			case 'c':
				mss_val = atoi(optarg);
				if ((retval = ioctl(fd, IVI_IOC_MSS_LIMIT, (void*)(&mss_val))) < 0) {
					printf("Error: failed to set mssclamping, code %d.\n", retval);
					goto out;
				}
				break;
			case 'H':
				hgw = 1;
				break;
			case 'p':
				if ((retval = inet_pton(AF_INET, optarg, (void*)(&(rule.prefix4)))) != 1) {
					printf("Error: failed to parse IPv4 prefix, code %d.\n", retval);
					retval = -1;
					goto out;
				}
				if ((retval = ioctl(fd, IVI_IOC_V4NET, &(rule.prefix4))) < 0) {
					printf("Error: failed to assign IPv4 network prefix, code %d.\n", retval);
					goto out;
				}		
				break;
			case 'l':
				rule.plen4 = atoi(optarg);
				temp = (rule.plen4 == 0) ? 0 : 0xffffffff << (32 - rule.plen4);  // Generate network mask
				if ((retval = ioctl(fd, IVI_IOC_V4MASK, &(temp))) < 0) {
					printf("Error: failed to assign IPv4 network prefix length, code %d.\n", retval);
					goto out;
				}
				break;
			case 'N':
				nat44 = 1;
				break;
			case 'A':
				if ((retval = inet_pton(AF_INET, optarg, (void*)(&v4addr))) != 1) {
					printf("Error: failed to parse IPv4 public address, code %d.\n", retval);
					retval = -1;
					goto out;
				}
				if ((retval = ioctl(fd, IVI_IOC_V4PUB, &(v4addr.s_addr))) < 0) {
					printf("Error: failed to assign IPv4 public address, code %d.\n", retval);
					goto out;
				}
				nat44 = 1;
				break;
			case 'P':
				if ((retval = inet_pton(AF_INET6, optarg, (void*)(&(rule.prefix6)))) != 1) {
					printf("Error: failed to parse IPv6 network prefix, code %d.\n", retval);
					retval = -1;
					goto out;
				}
				if ((retval = ioctl(fd, IVI_IOC_V6NET, &(rule.prefix6))) < 0) {
					printf("Error: failed to assign IPv6 network prefix, code %d.\n", retval);
					goto out;
				}
				break;
			case 'L':
				rule.plen6 = atoi(optarg);
				temp = rule.plen6 >> 3;  // counted in bytes
				if ((retval = ioctl(fd, IVI_IOC_V6MASK, &(temp))) < 0) {
					printf("Error: failed to assign IPv6 network prefix length, code %d.\n", retval);
					goto out;
				}
				break;
			case 'R':
				gma[0] = rule.ratio = atoi(optarg);
				break;
			case 'M':
				rule.adjacent = atoi(optarg);
				break;
			case 'f':
				if (strcmp(optarg, "postfix") == 0)
					rule.format = ADDR_FMT_POSTFIX;
				else if (strcmp(optarg, "suffix") == 0)
					rule.format = ADDR_FMT_SUFFIX;
				else {
					printf("Error: unknown format name %s. Must be 'postfix' or 'suffix'.\n", optarg);
					retval = -1;
					goto out;
				}
				break;
			case 'o':
				gma[1] = atoi(optarg);
				break;
			default:
				close(fd);
				usage(EXIT_FAILURE);
				break;
		}
	}
	
	// Set local addr format for HGW mode
	if (hgw) {
		if (rule.format == ADDR_FMT_POSTFIX) {
			if ((retval = ioctl(fd, IVI_IOC_POSTFIX, gma)) < 0) {
				printf("Error: failed to set addr format, code %d.\n", retval);
				goto out;
			}
			if ((retval = ioctl(fd, IVI_IOC_ADJACENT, (void*)(&rule.adjacent))) < 0) {
				printf("Error: failed to set adjacent parameter, code %d.\n", retval);
				goto out;
			}
		}
		else if (rule.format == ADDR_FMT_SUFFIX) {
			if ((retval = ioctl(fd, IVI_IOC_SUFFIX, gma)) < 0) {
				printf("Error: failed to set addr format, code %d.\n", retval);
				goto out;
			}
			if ((retval = ioctl(fd, IVI_IOC_ADJACENT, (void*)(&rule.adjacent))) < 0) {
				printf("Error: failed to set adjacent parameter, code %d.\n", retval);
				goto out;
			}
		}
		printf("Info: successfully set local address format.\n");
	}
	
	// Start IVI
	if (!hgw && !nat44) {
		if ((retval = ioctl(fd, IVI_IOC_CORE, 0)) < 0) {
			printf("Error: failed to set stateless core mode, code %d.\n", retval);
			goto out;
		}
		if ((retval = ioctl(fd, IVI_IOC_START, 0)) < 0) {
			printf("Error: failed to start IVI module, code %d.\n", retval);
			goto out;
		}
	} else if (hgw && !nat44) {
		if ((retval = ioctl(fd, IVI_IOC_NONAT, 0)) < 0) {
			printf("Error: failed to disable nat44, code %d.\n", retval);
			goto out;
		}
		if ((retval = ioctl(fd, IVI_IOC_START, 0)) < 0) {
			printf("Error: failed to start IVI module, code %d.\n", retval);
			goto out;
		}
	} else if (hgw && nat44) {
		if ((retval = ioctl(fd, IVI_IOC_NAT, 0)) < 0) {
			printf("Error: failed to enable nat44, code %d.\n", retval);
			goto out;
		}
		if ((retval = ioctl(fd, IVI_IOC_START, 0)) < 0) {
			printf("Error: failed to start IVI module, code %d.\n", retval);
			goto out;
		}
	} else {
		close(fd);
		usage(EXIT_FAILURE);
	}
	
	printf("Info: successfully started IVI module.\n");

out:
	close(fd);
	return retval;
}
