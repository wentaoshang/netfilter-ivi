#ifndef IVI_IOCTL_H
#define IVI_IOCTL_H

#include "ivi_config.h"

#define IVI_DEVNAME	"ivi"

#define IVI_IOCTL	'Z'

#define IVI_IOC_V4DEV	_IOW(IVI_IOCTL, 0x10, int)
#define IVI_IOC_V6DEV	_IOW(IVI_IOCTL, 0x11, int)
#define IVI_IOC_START	_IO(IVI_IOCTL, 0x12)
#define IVI_IOC_STOP	_IO(IVI_IOCTL, 0x13)
#define IVI_IOC_V4MAC	_IOW(IVI_IOCTL, 0x14, int)
#define IVI_IOC_V6MAC	_IOW(IVI_IOCTL, 0x15, int)

#define IVI_IOCTL_LEN	32

#endif /* IVI_IOCTL_H */

