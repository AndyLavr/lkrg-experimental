##
# Makefile for p_lkrg
#
# Author:
#  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
##

export CFLAGS="$CFLAGS"

P_OUTPUT = "output"
P_OUTPUT_CLI_CLI = "output/client/cli"
P_OUTPUT_CLI_KMOD = "output/client/kmod"

P_CLI_CMD = "p_lkrg-client"
P_CLI_KMOD = "p_lkrg_kmod_cli.ko"

obj-m += p_lkrg.o
p_lkrg-objs += src/modules/ksyms/p_resolve_ksym.o \
               src/modules/hashing/p_super_fast_hash.o \
               src/modules/hashing/p_crypto_sha1.o \
               src/modules/integrity_timer/p_integrity_timer.o \
               src/modules/kmod/p_kmod.o \
               src/modules/database/CPU.o \
               src/modules/database/arch/x86/IDT_MSR_CRx.o \
               src/modules/database/p_database.o \
               src/modules/notifiers/p_notifiers.o \
               src/modules/self-defense/hiding/p_hiding.o \
               src/modules/protected_features/p_rb_trees/p_rb_pids/p_rb_pids_tree.o \
               src/modules/protected_features/p_rb_trees/p_rb_inodes/p_rb_inodes_tree.o \
               src/modules/protected_features/p_rb_trees/p_rb_p_inodes/p_rb_p_inodes_tree.o \
               src/modules/protected_features/syscalls/p_sys_ptrace/p_sys_ptrace.o \
               src/modules/protected_features/syscalls/p_sys_execve/p_sys_execve.o \
               src/modules/protected_features/syscalls/p_do_exit/p_do_exit.o \
               src/modules/protected_features/syscalls/p_do_fork/p_do_fork.o \
               src/modules/protected_features/syscalls/p_signal_wrappers/p_sys_tgkill/p_sys_tgkill.o \
               src/modules/protected_features/syscalls/p_signal_wrappers/p_sys_tkill/p_sys_tkill.o \
               src/modules/protected_features/syscalls/p_signal_wrappers/p_sys_kill/p_sys_kill.o \
               src/modules/protected_features/syscalls/p_signal_wrappers/p_sys_rt_sigqueueinfo/p_sys_rt_sigqueueinfo.o \
               src/modules/protected_features/syscalls/p_signal_wrappers/p_sys_rt_tgsigqueueinfo/p_sys_rt_tgsigqueueinfo.o \
               src/modules/protected_features/protected_files_func/p_may_open/p_may_open.o \
               src/modules/protected_features/protected_process_func/p_write_enabled_file_bool/p_write_enabled_file_bool.o \
               src/modules/protected_features/protected_process_func/p_process_vm_rw/p_process_vm_rw.o \
               src/modules/protected_features/protected_process_func/p_kprobe_seq_start/p_kprobe_seq_start.o \
               src/modules/protected_features/p_protected_API.o \
               src/p_lkrg_main.o


all:
#	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules CONFIG_DEBUG_SECTION_MISMATCH=y
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD)/src/modules/kmod/client/kmod modules
	gcc -Wall -ggdb src/modules/kmod/client/cli/p_lkrg-client.c -o p_lkrg-client
	mkdir -p $(P_OUTPUT_CLI_CLI)
	mkdir -p $(P_OUTPUT_CLI_KMOD)
	mv $(PWD)/p_lkrg.ko $(P_OUTPUT)
	mv $(PWD)/p_lkrg-client $(P_OUTPUT_CLI_CLI)
	mv $(PWD)/src/modules/kmod/client/kmod/$(P_CLI_KMOD) $(P_OUTPUT_CLI_KMOD)

install:
	mkdir -p /lib/modules/`uname -r`/kernel/arch/x86/kernel/
	cp p_krd.ko /lib/modules/`uname -r`/kernel/arch/x86/kernel/p_krd.ko
	depmod /lib/modules/`uname -r`/kernel/arch/x86/kernel/p_krd.ko

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD)/src/modules/kmod/client/kmod clean
	$(RM) Module.markers modules.order
	$(RM) $(PWD)/src/modules/kmod/client/kmod/Module.markers
	$(RM) $(PWD)/src/modules/kmod/client/kmod/modules.order
	$(RM) -rf $(P_OUTPUT)
