#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "../modules/ivi_map.h"
#include "../modules/ivi_ioctl.h"

int get_ipv4_prefix_len(const char *arg, unsigned int *prefix, unsigned short *len) {
	unsigned int addr[4];
	if (sscanf(arg, "%u.%u.%u.%u/%hu", &addr[0], &addr[1], &addr[2], &addr[3], len) == 5) {
		*prefix = (addr[0] << 24) | (addr[1] << 16) | (addr[2] << 8) | addr[3];
		return 1;
	}
	else {
		return 0;
	}
}

int get_ipv6_prefix(const char *arg, unsigned char v6_prefix[]) {
	int i, pos = 0;
	unsigned short val;
	for (i = 0; i < 16; i++) {
		v6_prefix[i] = 0;
	}
	i = 0;
	while ((arg[pos] != '\0') && (strcmp(arg + pos, "::") != 0)
			&& (sscanf(arg + pos, "%hx:", &val) == 1) && (i < IVI_PREFIXLEN)) {
		v6_prefix[i] = val >> 8;
		v6_prefix[i + 1] = val & 0xff;
		i += 2;
		while ((arg[pos] != ':') && (arg[pos] != '\0')) {
			pos++;
		}
		if (arg[pos] != '\0') {
			pos++;
		}
	}
	return 1;
}

void print_4to6(struct rt_4to6_entry *rt, int count) {
	int i, j;

	for (i = 0; i < count; i++) {
		printf("\t%u.%u.%u.%u/%hu\t->\t",
				(rt + i)->v4prefix >> 24, ((rt + i)->v4prefix >> 16) & 0xff,
				((rt + i)->v4prefix >> 8) & 0xff, (rt + i)->v4prefix & 0xff,
				(rt + i)->v4len);
		for (j = 0; j < IVI_PREFIXLEN; j += 2) {
			if (j + 1 == IVI_PREFIXLEN) {
				printf("%hx:", (unsigned short)((rt + i)->v6prefix[j]) << 8);
			}
			else {
				printf("%hx:", ((unsigned short)((rt + i)->v6prefix[j]) << 8) | (rt + i)->v6prefix[j + 1]);
			}
		}
		printf(":/%d\n", IVI_PREFIXLEN * 8);
	}
}

void print_6to4(struct in6_addr *rt, int count) {
	int i, j;

	for (i = 0; i < count; i++) {
		printf("\t");
		for (j = 0; j < IVI_PREFIXLEN; j += 2) {
			if (j + 1 == IVI_PREFIXLEN) {
				printf("%hx:", (unsigned short)((rt + i)->s6_addr[j]) << 8);
			}
			else {
				printf("%hx:", ((unsigned short)((rt + i)->s6_addr[j]) << 8) | (rt + i)->s6_addr[j + 1]);
			}
		}
		printf(":/%d\n", IVI_PREFIXLEN * 8);
	}
}

int main(int argc, char *argv[]) {
	struct rt_4to6_entry *entry46;
	struct in6_addr *entry64;
	int retval, fd, flag;

	printf("IVI mapping configuration utility v0.1\n");
	
	if ((fd = open("/dev/ivi", 0)) < 0) {
		printf("Error: cannot open virtual device for ioctl, code %d.\n", fd);
		exit(-1);
	}

	flag = 0;

	if ((argc == 4) && (strcmp(argv[1], "add46") == 0)) {
		if ((entry46 = (struct rt_4to6_entry *)malloc(sizeof(struct rt_4to6_entry))) == NULL) {
			printf("Error: cannot allocate memory.\n");
			exit(-1);
		}
		if (get_ipv4_prefix_len(argv[2], &(entry46->v4prefix), &(entry46->v4len)) 
				&& get_ipv6_prefix(argv[3], entry46->v6prefix)) {
			flag = 1;
			retval = ioctl(fd, IVI_IOC_ADD46, entry46);
			if (retval == 0) {
				printf("Info: specified 4-to-6 mapping information is successfully added.\n");
			}
			else {
				printf("Error: failed to add 4-to-6 mapping information, code %d.\n", retval);
			}
		}
	}

	if ((argc == 3) && (strcmp(argv[1], "del46") == 0)) {
		if ((entry46 = (struct rt_4to6_entry *)malloc(sizeof(struct rt_4to6_entry))) == NULL) {
			printf("Error: cannot allocate memory.\n");
			exit(-1);
		}
		if (get_ipv4_prefix_len(argv[2], &(entry46->v4prefix), &(entry46->v4len))) {
			flag = 1;
			retval = ioctl(fd, IVI_IOC_DEL46, entry46);
			if (retval == 0) {
				printf("Info: specified 4-to-6 mapping information is successfully deleted.\n");
			}
			else {
				printf("Error: failed to delete 4-to-6 mapping information, code %d.\n", retval);
			}
		}
	}

	if ((argc == 3) && (strcmp(argv[1], "add64") == 0)) {
		if ((entry64 = (struct in6_addr *)malloc(sizeof(struct in6_addr))) == NULL) {
			printf("Error: cannot allocate memory.\n");
			exit(-1);
		}
		if (get_ipv6_prefix(argv[2], entry64->s6_addr)) {
			flag = 1;
			retval = ioctl(fd, IVI_IOC_ADD64, entry64);
			if (retval == 0) {
				printf("Info: specified 6-to-4 mapping information is successfully added.\n");
			}
			else {
				printf("Error: failed to add 6-to-4 mapping information, code %d.\n", retval);
			}
		}
	}

	if ((argc == 3) && (strcmp(argv[1], "del64") == 0)) {
		if ((entry64 = (struct in6_addr *)malloc(sizeof(struct in6_addr))) == NULL) {
			printf("Error: cannot allocate memory.\n");
			exit(-1);
		}
		if (get_ipv6_prefix(argv[2], entry64->s6_addr)) {
			flag = 1;
			retval = ioctl(fd, IVI_IOC_DEL64, entry64);
			if (retval == 0) {
				printf("Info: specified 6-to-4 mapping information is successfully deleted.\n");
			}
			else {
				printf("Error: failed to delete 6-to-4 mapping information, code %d.\n", retval);
			}
		}
	}

	if ((argc == 2) && (strcmp(argv[1], "list") == 0)) {
		flag = 1;
		printf("4-to-6 mapping information table:\n");
		retval = ioctl(fd, IVI_IOC_CNT46, 0);
		if (retval > 0) {
			if ((entry46 = (struct rt_4to6_entry *)malloc(sizeof(struct rt_4to6_entry) * retval)) == NULL) {
				printf("Error: cannot allocate memory.\n");
				exit(-1);
			}
			retval = ioctl(fd, IVI_IOC_LST46, entry46);
			print_4to6(entry46, retval);
		}
		else {
			printf("\t-- empty --\n");
		}
		printf("6-to-4 mapping information table:\n");
		retval = ioctl(fd, IVI_IOC_CNT64, 0);
		if (retval > 0) {
			if ((entry64 = (struct in6_addr *)malloc(sizeof(struct in6_addr) * retval)) == NULL) {
				printf("Error: cannot allocate memory.\n");
				exit(-1);
			}
			retval = ioctl(fd, IVI_IOC_LST64, entry64);
			print_6to4(entry64, retval);
		}
		else {
			printf("\t-- empty --\n");
		}
	}

	if (flag == 0) {
		printf("Usage: ivimap add46 [ipv4_prefix]/[length] [ipv6_prefix]\n");
		printf("              del46 [ipv4_prefix]/[length]\n");
		printf("              add64 [ipv6_prefix]\n");
		printf("              del64 [ipv6_prefix]\n");
		printf("              list\n");
	}

	close(fd);

	return retval;
}

