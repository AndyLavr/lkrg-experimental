/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept ptrace syscall
 *
 * Notes:
 *  - We are maintianing Red-Black tree of protected process pids. Ptrace hook
 *    provides guarantee that anyone who want to interact in any form (using
 *    ptrace syscall) with the protected process, will be intercepted and blocked
 *
 * Caveats:
 *  - None
 *
 * Timeline:
 *  - Created: 12.IX.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_PROTECTED_PROCESS_SYS_PTRACE_H
#define P_LKRG_PROTECTED_PROCESS_SYS_PTRACE_H

/* per-instance private data */
struct p_sys_ptrace_data {
    ktime_t entry_stamp;
};

int p_sys_ptrace_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs);
int p_sys_ptrace_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_install_sys_ptrace_hook(void);
void p_uninstall_sys_ptrace_hook(void);

#endif
