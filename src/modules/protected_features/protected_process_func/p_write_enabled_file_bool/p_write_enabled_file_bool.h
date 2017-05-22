/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept 'write_enabled_file_bool' function
 *
 * Notes:
 *  - *kprobes can be easily globally disabled using /sys interface:
 *    /sys/kernel/debug/kprobes/enabled
 *    To avoid situation when attacker globally siables our interceptions
 *    We need to force to fail this function
 *
 * Caveats:
 *  - None
 *
 * Timeline:
 *  - Created: 9.II.2017
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_PROTECTED_PROCESS_WRITE_EMABLED_FILE_BOOL_H
#define P_LKRG_PROTECTED_PROCESS_WRITE_EMABLED_FILE_BOOL_H

/* per-instance private data */
struct p_write_enabled_file_bool_data {
    ktime_t entry_stamp;
};


int p_write_enabled_file_bool_ret(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_write_enabled_file_bool_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_install_write_enabled_file_bool_hook(void);
void p_uninstall_write_enabled_file_bool_hook(void);

#endif
