/*
 * ivi_ioctl.c :
 *  IVI Configuration Interface Kernel Module
 *
 * by haoyu@cernet.edu.cn 2008.10.10
 *
 * Changes:
 *	Wentao Shang	:	Remove ivi mac io control code.
 *	Wentao Shang	:	Remove old ivi_map functions.
 */

#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif
#include <linux/module.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/netdevice.h>
#include <linux/uaccess.h>
#include "ivi_nf.h"
#include "ivi_xmit.h"
#include "ivi_ioctl.h"

static int ivi_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg) {
	int retval = 0;
	struct net_device *dev;
	char temp[IVI_IOCTL_LEN];

	switch (cmd) {
		case IVI_IOC_V4DEV:
			if (copy_from_user(temp, (char *)arg, IVI_IOCTL_LEN) > 0) {
				return -EACCES;
			}
			temp[IVI_IOCTL_LEN - 1] = 0;
			dev = dev_get_by_name(&init_net, temp);
			if (dev == NULL) {
				return -ENODEV;
			}
			retval = nf_getv4dev(dev);
			break;
		
		case IVI_IOC_V6DEV:
			if (copy_from_user(temp, (char *)arg, IVI_IOCTL_LEN) > 0) {
				return -EACCES;
			}
			temp[IVI_IOCTL_LEN - 1] = 0;
			dev = dev_get_by_name(&init_net, temp);
			if (dev == NULL) {
				return -ENODEV;
			}
			retval = nf_getv6dev(dev);
			break;
		
		case IVI_IOC_START:
			retval = nf_running(1);
			break;
		case IVI_IOC_STOP:
			retval = nf_running(0);
			break;

		default:
			retval = -ENOTTY;
	}
	return retval;
}

static int ivi_open(struct inode *inode, struct file *file) {
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "a new virtual device is opened for ioctl.\n");
#endif
	return 0;
}

static int ivi_release(struct inode *inode, struct file *file) {
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "a virtual device for ioctl is closed.\n");
#endif
	return 0;
}

struct file_operations ivi_ops = {
	.owner		=	THIS_MODULE,
	.ioctl		=	ivi_ioctl,
	.open		=	ivi_open,
	.release	=	ivi_release,
};

static int __init ivi_ioctl_init(void) {
	int retval;
	if ((retval = register_chrdev(IVI_IOCTL, IVI_DEVNAME, &ivi_ops)) < 0) {
		printk(KERN_ERR "failed to register ioctl as character device, code %d.\n", retval);
	}
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "IVI: module ivi_ioctl loaded with return value %d.\n", retval);
#endif
	return retval;
}
module_init(ivi_ioctl_init);

static void __exit ivi_ioctl_exit(void) {
	unregister_chrdev(IVI_IOCTL, IVI_DEVNAME);
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "IVI: module ivi_ioctl unloaded with return value.\n");
#endif
}
module_exit(ivi_ioctl_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ZHU Yuncheng <haoyu@cernet.edu.cn>");
MODULE_AUTHOR("Wentao Shang <wentaoshang@gmail.com>");
MODULE_DESCRIPTION("IVI Configuration Interface Kernel Module");
