/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept compat_rt_tgsigqueueinfo syscall
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
 *  - Created: 19.I.2018
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_PROTECTED_PROCESS_COMPAT_SYS_RT_TGSIGQUEUEINFO_H
#define P_LKRG_PROTECTED_PROCESS_COMPAT_SYS_RT_TGSIGQUEUEINFO_H

/* per-instance private data */
struct p_compat_sys_rt_tgsigqueueinfo_data {
    ktime_t entry_stamp;
};


int p_compat_sys_rt_tgsigqueueinfo_ret(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_compat_sys_rt_tgsigqueueinfo_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_install_compat_sys_rt_tgsigqueueinfo_hook(void);
void p_uninstall_compat_sys_rt_tgsigqueueinfo_hook(void);

#endif
