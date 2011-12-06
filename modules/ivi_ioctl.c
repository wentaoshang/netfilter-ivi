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
	__be16 tmp;
	
	switch (cmd) {
		case IVI_IOC_START:
			retval = nf_running(1);
			break;
		
		case IVI_IOC_STOP:
			retval = nf_running(0);
			break;
		
		case IVI_IOC_V4NET:
			if (copy_from_user(&v4addr, (__be32 *)arg, sizeof(__be32)) > 0) {
				return -EACCES;
			}
			v4addr = ntohl(v4addr);
			printk(KERN_INFO "ivi_ioctl: v4 address set to %08x.\n", v4addr);
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
		
		case IVI_IOC_POSTFIX:
			if (copy_from_user(&ratio, (__be16 *)arg, sizeof(__be16)) > 0) {
				return -EACCES;
			}
			printk(KERN_INFO "ivi_ioctl: ratio set to %04x.\n", ratio);
			if (copy_from_user(&offset, ((__be16 *)arg) + 1, sizeof(__be16)) > 0) {
				return -EACCES;
			}
			printk(KERN_INFO "ivi_ioctl: offset set to %04x.\n", offset);
			addr_fmt = ADDR_FMT_POSTFIX;
			printk(KERN_INFO "ivi_ioctl: addr_fmt set to %d.\n", addr_fmt);
			break;

		case IVI_IOC_SUFFIX:
			if (copy_from_user(&ratio, (__be16 *)arg, sizeof(__be16)) > 0) {
				return -EACCES;
			}
			printk(KERN_INFO "ivi_ioctl: ratio set to %04x.\n", ratio);
			if (copy_from_user(&offset, ((__be16 *)arg) + 1, sizeof(__be16)) > 0) {
				return -EACCES;
			}
			printk(KERN_INFO "ivi_ioctl: offset set to %04x.\n", offset);
			
			suffix = 0;
			tmp = ratio;
			while (tmp >> 1 != 0) {
				suffix++;
				tmp = tmp >> 1;
			}
			//printk("%04x\n", suffix);
			suffix = suffix << 12;
			//printk("%04x\n", suffix);
			suffix += offset & 0x0fff;
			//printk("%04x\n", suffix);
			printk(KERN_INFO "ivi_ioctl: suffix set to %04x.\n", suffix);
			addr_fmt = ADDR_FMT_SUFFIX;
			printk(KERN_INFO "ivi_ioctl: addr_fmt set to %d.\n", addr_fmt);
			break;

		case IVI_IOC_MSS_LIMIT:
			if (copy_from_user(&mss_limit, (__u16 *)arg, sizeof(__u16)) > 0) {
				return -EACCES;
			}
			printk(KERN_INFO "ivi_ioctl: mss limit set to %d.\n", mss_limit);
			break;

		case IVI_IOC_PD_DEFAULT:
			if (copy_from_user(v6default, (__u8 *)arg, 16) > 0) {
				return -EACCES;
			}
			printk(KERN_INFO "ivi_ioctl: default pd prefix set to %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x.\n", 
				ntohs(((__be16 *)v6default)[0]), ntohs(((__be16 *)v6default)[1]), ntohs(((__be16 *)v6default)[2]), ntohs(((__be16 *)v6default)[3]), 
				ntohs(((__be16 *)v6default)[4]), ntohs(((__be16 *)v6default)[5]), ntohs(((__be16 *)v6default)[6]), ntohs(((__be16 *)v6default)[7]));
			break;
		
		case IVI_IOC_PD_DEFAULT_LEN:
			if (copy_from_user(&v6defaultlen, (__be32 *)arg, sizeof(__be32)) > 0) {
				return -EACCES;
			}
			printk(KERN_INFO "ivi_ioctl: default pd prefix length set to %d.\n", v6defaultlen);
			break;
		
		default:
			retval = -ENOTTY;
	}
	return retval;
}

static int ivi_open(struct inode *inode, struct file *file) {
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "ivi_open: ivi virtual device is opened for ioctl.\n");
#endif
	return 0;
}

static int ivi_release(struct inode *inode, struct file *file) {
#ifdef IVI_DEBUG
	printk(KERN_DEBUG "ivi_release: ivi virtual device for ioctl is closed.\n");
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
