##
# Makefile for p_lkrg_kmod_cli
#
# Author:
#  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
##

obj-m += p_lkrg_kmod_cli.o
p_lkrg_kmod_cli-objs += src/p_lkrg_cli.o


all:
#	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules CONFIG_DEBUG_SECTION_MISMATCH=y
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules


clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	$(RM) Module.markers modules.order
