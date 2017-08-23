/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Protected features main module
 *
 * Notes:
 *  - None
 *
 * Timeline:
 *  - Created: 12.IX.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_PROTECTED_FEATURES_API_H
#define P_PROTECTED_FEATURES_API_H

#include "p_rb_trees/p_rb_pids/p_rb_pids_tree.h"
#include "p_rb_trees/p_rb_inodes/p_rb_inodes_tree.h"
#include "p_rb_trees/p_rb_p_inodes/p_rb_p_inodes_tree.h"
#include "syscalls/p_sys_ptrace/p_sys_ptrace.h"
#include "syscalls/p_sys_execve/p_sys_execve.h"
#include "syscalls/p_do_exit/p_do_exit.h"
#include "syscalls/p_do_fork/p_do_fork.h"
#include "syscalls/p_signal_wrappers/p_sys_tgkill/p_sys_tgkill.h"
#include "syscalls/p_signal_wrappers/p_sys_tkill/p_sys_tkill.h"
#include "syscalls/p_signal_wrappers/p_sys_kill/p_sys_kill.h"
#include "syscalls/p_signal_wrappers/p_sys_rt_sigqueueinfo/p_sys_rt_sigqueueinfo.h"
#include "syscalls/p_signal_wrappers/p_sys_rt_tgsigqueueinfo/p_sys_rt_tgsigqueueinfo.h"
#include "protected_files_func/p_may_open/p_may_open.h"
#include "protected_process_func/p_write_enabled_file_bool/p_write_enabled_file_bool.h"
#include "protected_process_func/p_process_vm_rw/p_process_vm_rw.h"
#include "protected_process_func/p_kprobe_seq_start/p_kprobe_seq_start.h"

#define P_PROTECTED_FEATURES_INIT "/root/.p_lkrg-pf"

#define P_LKRG_KMOD_CLI "/root/p_lkrg-beta/output/client/kmod/p_lkrg_kmod_cli.ko"
#define P_LKRG_USER_CLI "/root/p_lkrg-beta/output/client/cli/p_lkrg-client"

#define P_PROTECTED_FILES_OPT_FILE 0x1
#define P_PROTECTED_FILES_OPT_LOGS 0x2


struct p_inode_work_struct {

   struct work_struct p_worker;
   unsigned int p_protected_files;
   unsigned long p_inode;
   char *p_path_val;

};

void p_protected_lower_caps(pid_t p_arg);
void p_protected_raise_caps(pid_t p_arg);

int p_protect_process(pid_t p_arg);
int p_unprotect_process(pid_t p_arg);
int p_is_protected_pid(pid_t p_arg);

int p_protect_inode(struct inode *p_inode, struct inode *p_parent_inode, unsigned int p_opt);
int p_unprotect_inode(struct inode *p_arg, unsigned int p_opt);
int p_is_protected_inode(struct inode *p_arg);

int p_protect_p_inode(struct inode *p_inode);
int p_unprotect_p_inode(struct inode *p_arg);
struct p_protected_p_inode *p_is_protected_p_inode(struct inode *p_arg);

int p_get_inode(char *p_arg, struct inode **p_out_inode, struct inode **p_parent_out_inode, struct path *p_path);

void p_offload_protected_inode(unsigned int p_protected_files, unsigned long p_inode, char *p_path_val);
void p_offload_protected_inode_run(struct work_struct *p_arg);

int p_protected_features_init(void);
void p_protected_features_exit(void);

#endif
