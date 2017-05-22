/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept execve syscall
 *
 * Notes:
 *  - To make it works, we must intercept pre-syscall to check what is the desired filename.
 *    Path could be in complicated form, and could be a symlink. We need to resolve it to get
 *    Real Path Name and compare if it is going to be executed protected process. If yes, we
 *    need to inform 'other' syscalls that specific PID must be protected. To do it, we inject
 *    new PID in the Red-Black tree which we maintain...
 *
 * Caveats:
 *  - Any [k]probes run under IRQ disabled, even documentation says that kretprobe is not.
 *    That's not correct and have specific implication. E.g. functions like 'kern_path' if
 *    trying to parse not existing pathname, can call 'gentle' function which checks if IRQs
 *    are enabled. If not they crash! That's why we reenabling IRQs here...
 *
 * Timeline:
 *  - Created: 12.IX.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_PROTECTED_PROCESS_SYS_EXECVE_H
#define P_LKRG_PROTECTED_PROCESS_SYS_EXECVE_H

#define P_MAX_PATH PATH_MAX + 0x20 /* For weirdos used by d_path */


/* per-instance private data */
struct p_sys_execve_data {
    ktime_t entry_stamp;
};


struct inode *p_get_inode_from_task(struct task_struct *p_arg);

int p_sys_execve_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs);
int p_sys_execve_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_install_sys_execve_hook(void);
void p_uninstall_sys_execve_hook(void);

#endif
