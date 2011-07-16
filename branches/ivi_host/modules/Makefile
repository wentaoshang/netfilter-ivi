obj-m		:=	ivi_map.o ivi_ioctl.o ivi_nf.o ivi_xmit.o
KERNELDIR	:=	/lib/modules/$(shell uname -r)/build
PWD		:=	$(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -rf *.ko *.o *.mod.c core Module.symvers Module.markers modules.order
