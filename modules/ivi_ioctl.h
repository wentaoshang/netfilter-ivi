#ifndef IVI_IOCTL_H
#define IVI_IOCTL_H

#include "ivi_config.h"

#define IVI_DEVNAME	"ivi"

#define IVI_IOCTL	324

#define IVI_IOC_V4DEV	_IOW(IVI_IOCTL, 0x10, int)
#define IVI_IOC_V6DEV	_IOW(IVI_IOCTL, 0x11, int)
#define IVI_IOC_START	_IO(IVI_IOCTL, 0x12)
#define IVI_IOC_STOP	_IO(IVI_IOCTL, 0x13)

#define IVI_IOC_V4NET	_IOW(IVI_IOCTL, 0x14, int)
#define IVI_IOC_V4MASK	_IOW(IVI_IOCTL, 0x15, int)
#define IVI_IOC_V6NET	_IOW(IVI_IOCTL, 0x16, int)
#define IVI_IOC_V6MASK	_IOW(IVI_IOCTL, 0x17, int)
#define IVI_IOC_V4PUB	_IOW(IVI_IOCTL, 0x18, int)
#define IVI_IOC_NAT	_IO(IVI_IOCTL, 0x19)
#define IVI_IOC_NONAT	_IO(IVI_IOCTL, 0x1a)

#define IVI_IOC_POSTFIX	_IOW(IVI_IOCTL, 0x1b, int)
#define IVI_IOC_SUFFIX	_IOW(IVI_IOCTL, 0x1c, int)

#define IVI_IOC_MSS_LIMIT	_IOW(IVI_IOCTL, 0x1d, int)

#define IVI_IOC_ADJACENT	_IOW(IVI_IOCTL, 0x20, int)

#define IVI_IOC_ADD_RULE	_IOW(IVI_IOCTL, 0x21, int)

#define IVI_IOC_CORE	_IOW(IVI_IOCTL, 0x22, int)

#define IVI_IOCTL_LEN	32

#ifdef __KERNEL__

extern int ivi_ioctl_init(void);
extern void ivi_ioctl_exit(void);

#endif

#endif /* IVI_IOCTL_H */

