/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept kill syscall
 *
 * Notes:
 *  - Only Protected processes can send signals to each other.
 *    Intercept all signal sending API to check who is requesting
 *    this work and do not allow normal processes to continue if
 *    destination pid is coresponding to Protected Process.
 *
 * Caveats:
 *  - None
 *
 * Timeline:
 *  - Created: 25.IX.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_PROTECTED_PROCESS_SYS_KILL_H
#define P_LKRG_PROTECTED_PROCESS_SYS_KILL_H

/* per-instance private data */
struct p_sys_kill_data {
    ktime_t entry_stamp;
};


int p_sys_kill_ret(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_sys_kill_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_install_sys_kill_hook(void);
void p_uninstall_sys_kill_hook(void);

#endif
