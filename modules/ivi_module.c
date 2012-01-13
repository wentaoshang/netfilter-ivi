#include <linux/module.h>

#include "ivi_rule.h"
#include "ivi_rule6.h"
#include "ivi_map.h"
#include "ivi_map_tcp.h"
#include "ivi_nf.h"
#include "ivi_ioctl.h"

static int __init ivi_module_init(void) {
	int retval = 0;
	if ((retval = ivi_rule_init()) < 0) {
		return retval;
	}
	if ((retval = ivi_rule6_init()) < 0) {
		return retval;
	}
	if ((retval = ivi_map_init()) < 0) {
		return retval;
	}
	if ((retval = ivi_map_tcp_init()) < 0) {
		return retval;
	}
	if ((retval = ivi_nf_init()) < 0) {
		return retval;
	}
	if ((retval = ivi_ioctl_init()) < 0) {
		return retval;
	}
	return 0;
}
module_init(ivi_module_init);

static void __exit ivi_module_exit(void) {
	ivi_ioctl_exit();
	ivi_nf_exit();
	ivi_map_tcp_exit();
	ivi_map_exit();
	ivi_rule6_exit();
	ivi_rule_exit();
}
module_exit(ivi_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ZHU Yuncheng <haoyu@cernet.edu.cn>");
MODULE_AUTHOR("Wentao Shang <wentaoshang@gmail.com>");
MODULE_DESCRIPTION("IVI Kernel Module");
