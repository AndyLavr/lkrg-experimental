/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept tkill syscall
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
 *  - Created: 17.IX.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_PROTECTED_PROCESS_SYS_TKILL_H
#define P_LKRG_PROTECTED_PROCESS_SYS_TKILL_H

/* per-instance private data */
struct p_sys_tkill_data {
    ktime_t entry_stamp;
};


int p_sys_tkill_ret(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_sys_tkill_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_install_sys_tkill_hook(void);
void p_uninstall_sys_tkill_hook(void);

#endif
