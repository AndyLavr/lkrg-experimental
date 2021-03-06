/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept exit syscall
 *
 * Notes:
 *  - We are maintianing Red-Black tree of protected process pids. When protected
 *    process dies/exists we need to update RB tree.
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

#ifndef P_LKRG_PROTECTED_PROCESS_DO_EXIT_H
#define P_LKRG_PROTECTED_PROCESS_DO_EXIT_H

/* per-instance private data */
struct p_do_exit_data {
    ktime_t entry_stamp;
};


int p_do_exit_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs);
int p_do_exit_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_install_do_exit_hook(void);
void p_uninstall_do_exit_hook(void);

#endif
