/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept compat_execveat syscall
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
 *  - Created: 17.I.2018
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)

#ifndef P_LKRG_PROTECTED_PROCESS_COMPAT_SYS_EXECVEAT_H
#define P_LKRG_PROTECTED_PROCESS_COMPAT_SYS_EXECVEAT_H

/* per-instance private data */
struct p_compat_sys_execveat_data {
    ktime_t entry_stamp;
};

int p_compat_sys_execveat_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs);
int p_compat_sys_execveat_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_install_compat_sys_execveat_hook(void);
void p_uninstall_compat_sys_execveat_hook(void);

#endif

#endif
