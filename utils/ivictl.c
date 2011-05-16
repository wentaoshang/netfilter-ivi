#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "../modules/ivi_ioctl.h"

int main(int argc, char *argv[]) {
	char v4dev[IVI_IOCTL_LEN], v6dev[IVI_IOCTL_LEN];
	int retval, fd, flag;

	printf("IVI mapping controller utility v0.1\n");
	
	if ((fd = open("/dev/ivi", 0)) < 0) {
		printf("Error: cannot open virtual device for ioctl, code %d.\n", fd);
		exit(-1);
	}

	flag = 0;

	if ((argc == 4) && (strcmp(argv[1], "start") == 0)) {
		flag = 1;
		strncpy(v4dev, argv[2], IVI_IOCTL_LEN);
		strncpy(v6dev, argv[3], IVI_IOCTL_LEN);
		if ((retval = ioctl(fd, IVI_IOC_V4DEV, v4dev)) < 0) {
			printf("Error: failed to assign IPv4 device, code %d.\n", retval);
		}
		else if ((retval = ioctl(fd, IVI_IOC_V6DEV, v6dev)) < 0) {
			printf("Error: failed to assign IPv6 device, code %d.\n", retval);
		}
		else if ((retval = ioctl(fd, IVI_IOC_START, 0)) != 1) {
			printf("Error: failed to start IVI module, code %d.\n", retval);
		}
		else {
			printf("Info: successfully started IVI module.\n");
		}
	}

	if ((argc == 2) && (strcmp(argv[1], "stop") == 0)) {
		flag = 1;
		if ((retval = ioctl(fd, IVI_IOC_STOP, 0)) != 0) {
			printf("Error: failed to stop IVI module, code %d.\n", retval);
		}
		else {
			printf("Info: successfully stopped IVI module.\n");
		}
	}

	if (flag == 0) {
		printf("Usage: ivictl start [ipv4_device] [ipv6_device]\n");
		printf("              stop\n");
	}

	close(fd);

	return retval;
}
