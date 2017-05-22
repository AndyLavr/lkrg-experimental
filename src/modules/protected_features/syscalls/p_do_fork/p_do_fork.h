/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept fork syscall
 *
 * Notes:
 *  - We are maintianing Red-Black tree of protected process pids. When protected
 *    process forks, child must be protected as well! We need to update RB tree.
 *
 * Caveats:
 *  - None
 *
 * Timeline:
 *  - Created: 13.IX.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_PROTECTED_PROCESS_DO_FORK_H
#define P_LKRG_PROTECTED_PROCESS_DO_FORK_H

/* per-instance private data */
struct p_do_fork_data {
    ktime_t entry_stamp;
};


int p_do_fork_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs);
int p_do_fork_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_install_do_fork_hook(void);
void p_uninstall_do_fork_hook(void);

#endif
