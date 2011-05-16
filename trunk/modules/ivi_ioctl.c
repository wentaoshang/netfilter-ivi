/*
 * ivi_ioctl.c :
 *  IVI Configuration Interface Kernel Module
 *
 * by haoyu@cernet.edu.cn 2008.10.10
 *
 * Changes:
 *	Wentao Shang	:	Remove ivi mac io control code.
 *	Wentao Shang	:	Remove old ivi_map functions.
 *	Wentao Shang	:	Add new control codes for ivi and nat filter address configuration.
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
#include "ivi_config.h"

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
			printk(KERN_INFO "ivi_ioctl: v4 device set to %s.\n", temp);
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
			printk(KERN_INFO "ivi_ioctl: v6 device set to %s.\n", temp);
			break;
		
		case IVI_IOC_START:
			retval = nf_running(1);
			break;
		
		case IVI_IOC_STOP:
			retval = nf_running(0);
			break;
		
		case IVI_IOC_V4NET:
			if (copy_from_user(&v4network, (__be32 *)arg, sizeof(__be32)) > 0) {
				return -EACCES;
			}
			v4network = ntohl(v4network);
			printk(KERN_INFO "ivi_ioctl: v4 network set to %08x.\n", v4network);
			break;
		
		case IVI_IOC_V4MASK:
			if (copy_from_user(&v4mask, (__be32 *)arg, sizeof(__be32)) > 0) {
				return -EACCES;
			}
			printk(KERN_INFO "ivi_ioctl: v4 network mask set to %08x.\n", v4mask);
			break;
		
		case IVI_IOC_V6NET:
			if (copy_from_user(v6prefix, (__u8 *)arg, 16) > 0) {
				return -EACCES;
			}
			printk(KERN_INFO "ivi_ioctl: v6 prefix set to %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x.\n", 
				ntohs(((__be16 *)v6prefix)[0]), ntohs(((__be16 *)v6prefix)[1]), ntohs(((__be16 *)v6prefix)[2]), ntohs(((__be16 *)v6prefix)[3]), 
				ntohs(((__be16 *)v6prefix)[4]), ntohs(((__be16 *)v6prefix)[5]), ntohs(((__be16 *)v6prefix)[6]), ntohs(((__be16 *)v6prefix)[7]));
			break;
		
		case IVI_IOC_V6MASK:
			if (copy_from_user(&v6prefixlen, (__be32 *)arg, sizeof(__be32)) > 0) {
				return -EACCES;
			}
			printk(KERN_INFO "ivi_ioctl: v6 prefix length set to %d.\n", v6prefixlen);
			break;
		
		case IVI_IOC_V4PUB:
			if (copy_from_user(&v4publicaddr, (__be32 *)arg, sizeof(__be32)) > 0) {
				return -EACCES;
			}
			v4publicaddr = ntohl(v4publicaddr);
			printk(KERN_INFO "ivi_ioctl: v4 public address set to %08x.\n", v4publicaddr);
			break;
		
		case IVI_IOC_NAT:
			use_nat44 = 1;
			printk(KERN_INFO "ivi_ioctl: nat44 enabled.\n");
			break;
		
		case IVI_IOC_NONAT:
			use_nat44 = 0;
			printk(KERN_INFO "ivi_ioctl: nat44 disabled.\n");
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
