#ifndef IVI_IOCTL_H
#define IVI_IOCTL_H

#include "ivi_config.h"

#define IVI_DEVNAME	"ivi"

#define IVI_IOCTL	324

#define IVI_IOC_START	_IO(IVI_IOCTL, 0x12)
#define IVI_IOC_STOP	_IO(IVI_IOCTL, 0x13)

#define IVI_IOC_V4NET	_IOW(IVI_IOCTL, 0x14, int)
#define IVI_IOC_V4MASK	_IOW(IVI_IOCTL, 0x15, int)
#define IVI_IOC_V6NET	_IOW(IVI_IOCTL, 0x16, int)
#define IVI_IOC_V6MASK	_IOW(IVI_IOCTL, 0x17, int)

#define IVI_IOC_POSTFIX	_IOW(IVI_IOCTL, 0x1b, int)
#define IVI_IOC_SUFFIX	_IOW(IVI_IOCTL, 0x1c, int)

#define IVI_IOC_MSS_LIMIT	_IOW(IVI_IOCTL, 0x1d, int)

#endif /* IVI_IOCTL_H */

